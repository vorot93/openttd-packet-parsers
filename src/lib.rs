#![allow(unreachable_code)]

mod client_get_list;
mod master_response_list;
mod newgrf;
mod server_detail_info;
mod server_register;
mod server_response;
mod server_unregister;
mod util;

pub use crate::{
    client_get_list::*,
    master_response_list::*,
    newgrf::{ActiveNewGrf, NewGRFHash},
    server_detail_info::*,
    server_register::*,
    server_response::{ProtocolVer, ServerResponse},
    server_unregister::*,
};
use crate::{newgrf::newgrf_md5, util::*};
use byteorder::{LittleEndian, WriteBytesExt};
use nom::{
    combinator::{map, map_opt},
    multi::count,
    number::complete::*,
    sequence::{tuple, Tuple},
    *,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{collections::BTreeMap, ffi::CString};
use strum::EnumDiscriminants;

/// OpenTTD UDP network packet
#[derive(Clone, Debug, PartialEq, EnumDiscriminants)]
#[strum_discriminants(repr(u8))]
#[strum_discriminants(derive(IntoPrimitive, TryFromPrimitive))]
pub enum UdpPacket {
    ClientFindServer,
    ServerResponse(ServerResponse),
}

impl UdpPacket {
    /// Parse a UDP packet
    pub fn from_bytes(input: &[u8]) -> IResult<&[u8], UdpPacket> {
        let (input, (_, packet_type)) = (
            le_u16,
            map_opt(le_u8, |v| UdpPacketDiscriminants::try_from(v).ok()),
        )
            .parse(input)?;
        match packet_type {
            UdpPacketDiscriminants::ClientFindServer => Ok((input, UdpPacket::ClientFindServer)),
            UdpPacketDiscriminants::ServerResponse => {
                map(ServerResponse::from_bytes, UdpPacket::ServerResponse).parse(input)
            }
        }
    }
}

impl UdpPacket {
    pub fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
        let buf = &mut vec![];
        buf.push(UdpPacketDiscriminants::from(self).into());

        if let UdpPacket::ServerResponse(data) = self {
            data.write_pkt(buf)?
        };

        let mut out = vec![];
        out.write_u16::<LittleEndian>(buf.len() as u16 + 2)?;
        out.append(buf);

        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, EnumDiscriminants)]
#[strum_discriminants(repr(u8))]
#[strum_discriminants(derive(IntoPrimitive, TryFromPrimitive))]
pub enum CoordinatorPacket {
    GcError,
    ServerRegister,
    GcRegisterAck,
    ServerUpdate,
    ClientListing(ClientListingPacket),
    GcListing(GcListingPacket),
    ClientConnect,
    GcConnecting,
    SerCliConnectFailed,
    GcConnectFailed,
    ClientConnected,
    GcDirectConnect,
    GcStunRequest,
    SerCliStunResult,
    GcStunConnect,
    GcNewgrfLookup(GcNewgrfLookupPacket),
    GcTurnConnect,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClientListingPacket {
    pub openttd_revision: CString,

    pub newgrf_lookup_table_cursor: u32,
}

impl ByteWriter for ClientListingPacket {
    fn write_pkt(&self, out: &mut Vec<u8>) -> std::io::Result<()> {
        out.extend_from_slice(self.openttd_revision.to_bytes_with_nul());
        out.write_u32::<LittleEndian>(self.newgrf_lookup_table_cursor)?;
        Ok(())
    }
}

impl PacketPayload for ClientListingPacket {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(
            tuple((read_cstring, le_u32)),
            |(openttd_revision, newgrf_lookup_table_cursor)| Self {
                openttd_revision,
                newgrf_lookup_table_cursor,
            },
        )
        .parse(input)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GcListingPacket {
    pub servers: Vec<GcListingServer>,
}

impl ByteWriter for GcListingPacket {
    fn write_pkt(&self, out: &mut Vec<u8>) -> std::io::Result<()> {
        out.write_u16::<LittleEndian>(self.servers.len() as u16)?;
        for server in &self.servers {
            server.write_pkt(out)?;
        }
        Ok(())
    }
}

impl PacketPayload for GcListingPacket {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, num) = le_u16(input)?;
        map(count(GcListingServer::from_bytes, num.into()), |servers| {
            Self { servers }
        })
        .parse(input)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GcListingServer {
    pub address: CString,
    pub server_info: ServerResponse,
}

impl ByteWriter for GcListingServer {
    fn write_pkt(&self, out: &mut Vec<u8>) -> std::io::Result<()> {
        out.extend_from_slice(self.address.to_bytes_with_nul());
        self.server_info.write_pkt(out)?;
        Ok(())
    }
}

impl PacketPayload for GcListingServer {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(
            tuple((read_cstring, ServerResponse::from_bytes)),
            |(address, server_info)| Self {
                address,
                server_info,
            },
        )
        .parse(input)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GcNewgrfLookupPacket {
    pub newgrf_lookup_table_cursor: u32,
    pub newgrfs: BTreeMap<u32, (u32, NewGRFHash, CString)>,
}

impl ByteWriter for GcNewgrfLookupPacket {
    fn write_pkt(&self, out: &mut Vec<u8>) -> std::io::Result<()> {
        out.write_u32::<LittleEndian>(self.newgrf_lookup_table_cursor)?;
        out.write_u16::<LittleEndian>(self.newgrfs.len() as u16)?;
        for (index, (grfid, hash, name)) in &self.newgrfs {
            out.write_u32::<LittleEndian>(*index)?;
            out.write_u32::<LittleEndian>(*grfid)?;
            out.extend_from_slice(&hash.0);
            out.extend_from_slice(name.to_bytes_with_nul());
        }
        Ok(())
    }
}

impl PacketPayload for GcNewgrfLookupPacket {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, newgrf_lookup_table_cursor) = le_u32(input)?;
        let (input, num) = le_u16(input)?;
        map(
            count(
                tuple((le_u32, le_u32, newgrf_md5, read_cstring)),
                num.into(),
            ),
            move |newgrfs| Self {
                newgrf_lookup_table_cursor,
                newgrfs: newgrfs
                    .into_iter()
                    .map(|(index, grfid, hash, name)| (index, (grfid, hash, name)))
                    .collect(),
            },
        )
        .parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn fixtures() -> Vec<(Vec<u8>, UdpPacket)> {
        vec![(hex!("030000").into(), UdpPacket::ClientFindServer)]
    }

    #[test]
    fn test_parse_packet() {
        for (input, expectation) in fixtures() {
            let result = UdpPacket::from_bytes(&input).unwrap();

            assert_eq!(expectation, result.1);
        }
    }

    #[test]
    fn test_write_packet() {
        for (expectation, input) in fixtures() {
            let result = input.to_bytes().unwrap();

            assert_eq!(expectation, result);
        }
    }
}
