use crate::util::*;
use byteorder::WriteBytesExt;
use nom::{
    self,
    combinator::{map, map_opt},
    number::complete::*,
    sequence::pair,
    *,
};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ServerListType {
    IPv4,
    IPv6,
    Autodetect,
}

impl From<ServerListType> for u8 {
    fn from(v: ServerListType) -> Self {
        use ServerListType::*;

        match v {
            IPv4 => 0,
            IPv6 => 1,
            Autodetect => 2,
        }
    }
}

impl ServerListType {
    fn from_num(v: u8) -> Option<Self> {
        use ServerListType::*;

        match v {
            0 => Some(IPv4),
            1 => Some(IPv6),
            2 => Some(Autodetect),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClientGetListData {
    pub master_server_version: u8,
    pub request_type: ServerListType,
}

impl ByteWriter for ClientGetListData {
    fn write_pkt(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        buf.write_u8(self.master_server_version)?;
        buf.write_u8(self.request_type.into())?;

        Ok(())
    }
}

impl PacketPayload for ClientGetListData {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(
            pair(le_u8, map_opt(le_u8, ServerListType::from_num)),
            |(master_server_version, request_type)| Self {
                master_server_version,
                request_type,
            },
        )
        .parse(input)
    }
}
