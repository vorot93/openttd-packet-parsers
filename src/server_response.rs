use crate::{newgrf::ActiveNewGrfDiscriminants, util::*, ActiveNewGrf};
use byteorder::{LittleEndian, WriteBytesExt};
use chrono::prelude::*;
use nom::{self, combinator::map, number::complete::*, sequence::Tuple, *};
use num_enum::TryFromPrimitive;
use std::ffi::CString;

#[derive(Clone, Debug, PartialEq)]
pub enum ProtocolVer {
    V6,
}

impl<'a> From<&'a ProtocolVer> for u8 {
    fn from(v: &'a ProtocolVer) -> u8 {
        match *v {
            ProtocolVer::V6 => 6,
        }
    }
}

impl ByteWriter for ProtocolVer {
    fn write_pkt(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        buf.push(self.into());
        match *self {
            ProtocolVer::V6 => {}
        }
        Ok(())
    }
}

fn protocol_ver(input: &[u8]) -> IResult<&[u8], ProtocolVer> {
    let (input, protocol_num) = le_u8(input)?;
    match protocol_num {
        6 => Ok((input, ProtocolVer::V6)),
        _ => Err(nom::Err::Failure(nom::error::Error {
            input,
            code: nom::error::ErrorKind::OneOf,
        })),
    }
}

fn timestamp(input: &[u8]) -> IResult<&[u8], DateTime<Utc>> {
    map(le_u32, datetime_from_ts).parse(input)
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerResponse {
    pub gamescript_version: u32,
    pub gamescript_name: CString,
    pub active_newgrf: ActiveNewGrf,
    pub game_date: DateTime<Utc>,
    pub start_date: DateTime<Utc>,
    pub max_companies: u8,
    pub current_companies: u8,
    pub max_spectators: u8,
    pub server_name: CString,
    pub server_revision: CString,
    pub server_lang: u8,
    pub use_password: bool,
    pub clients_max: u8,
    pub clients_on: u8,
    pub spectators_on: u8,
    pub map_name: CString,
    pub map_width: u16,
    pub map_height: u16,
    pub map_set: u8,
    pub dedicated: bool,
}

impl ByteWriter for ServerResponse {
    fn write_pkt(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        ProtocolVer::V6.write_pkt(buf)?;

        buf.push(ActiveNewGrfDiscriminants::from(&self.active_newgrf).into());

        buf.write_u32::<LittleEndian>(self.gamescript_version)?;
        buf.append(&mut self.gamescript_name.clone().into_bytes_with_nul());

        match &self.active_newgrf {
            ActiveNewGrf::OnlyId(ids) => {
                buf.push(ids.len().try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "NewGRF maximum number is 255",
                    )
                })?);
                for (&id, hash) in ids {
                    buf.write_u32::<LittleEndian>(id)?;
                    buf.extend_from_slice(&hash.0);
                }
            }
            ActiveNewGrf::Full(ids) => {
                buf.push(ids.len().try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "NewGRF maximum number is 255",
                    )
                })?);
                for (&id, (hash, name)) in ids {
                    buf.write_u32::<LittleEndian>(id)?;
                    buf.extend_from_slice(&hash.0);
                    buf.append(&mut name.clone().into_bytes_with_nul());
                }
            }
            ActiveNewGrf::Lookup(ids) => {
                buf.push(ids.len().try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "NewGRF maximum number is 255",
                    )
                })?);
                for &id in ids {
                    buf.write_u32::<LittleEndian>(id)?;
                }
            }
        }

        buf.write_u32::<LittleEndian>(self.game_date.timestamp() as u32)?;
        buf.write_u32::<LittleEndian>(self.start_date.timestamp() as u32)?;

        buf.push(self.max_companies);
        buf.push(self.current_companies);
        buf.push(self.max_spectators);

        buf.append(&mut self.server_name.clone().into_bytes_with_nul());
        buf.append(&mut self.server_revision.clone().into_bytes_with_nul());
        buf.push(self.server_lang);
        buf.push(if self.use_password { 1 } else { 0 });
        buf.push(self.clients_max);
        buf.push(self.clients_on);
        buf.push(self.spectators_on);

        buf.append(&mut self.map_name.clone().into_bytes_with_nul());
        buf.write_u16::<LittleEndian>(self.map_width)?;
        buf.write_u16::<LittleEndian>(self.map_height)?;
        buf.push(self.map_set);
        buf.push(if self.dedicated { 1 } else { 0 });

        Ok(())
    }
}

impl PacketPayload for ServerResponse {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (_, kind, gamescript_version, gamescript_name)) =
            (protocol_ver, le_u8, le_u32, read_cstring).parse(input)?;

        let (input, active_newgrf) = ActiveNewGrf::from_bytes(
            input,
            ActiveNewGrfDiscriminants::try_from_primitive(kind).map_err(|_| {
                nom::Err::Failure(nom::error::Error {
                    input,
                    code: nom::error::ErrorKind::OneOf,
                })
            })?,
        )?;

        let (
            input,
            (
                game_date,
                start_date,
                max_companies,
                current_companies,
                max_spectators,
                server_name,
                server_revision,
                server_lang,
                use_password,
                clients_max,
                clients_on,
                spectators_on,
                map_name,
                map_width,
                map_height,
                map_set,
                dedicated,
            ),
        ) = (
            timestamp,
            timestamp,
            le_u8,
            le_u8,
            le_u8,
            read_cstring,
            read_cstring,
            le_u8,
            map(le_u8, |v| v > 0),
            le_u8,
            le_u8,
            le_u8,
            read_cstring,
            le_u16,
            le_u16,
            le_u8,
            map(le_u8, |v| v > 0),
        )
            .parse(input)?;
        Ok((
            input,
            Self {
                gamescript_version,
                gamescript_name,
                active_newgrf,
                game_date,
                start_date,
                max_companies,
                current_companies,
                max_spectators,
                server_name,
                server_revision,
                server_lang,
                use_password,
                clients_max,
                clients_on,
                spectators_on,
                map_name,
                map_width,
                map_height,
                map_set,
                dedicated,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewGRFHash;
    use hex_literal::hex;
    use maplit::btreemap;

    pub(crate) fn fixtures() -> (Vec<u8>, ServerResponse) {
        let b = hex!(
            "0600FFFFFFFF0003444E070048B3F9E4FD0DF2A72B5F44D3C8A2F4A04D4703052E96B9AB2BEA686BFF94961AD433A70132323322316180DA1BA6444A06CD17F8FA79D60A63EC0A0063EC0A000F000A4F6E6C79467269656E6473204F70656E5454442053657276657220233100312E352E3300160019000052616E646F6D204D617000000400040101"
        )
        .to_vec();

        let srv = ServerResponse {
            gamescript_version: u32::MAX,
            gamescript_name: CString::default(),

            active_newgrf: ActiveNewGrf::OnlyId(btreemap! {
                0x00074e44 => NewGRFHash(hex!("48b3f9e4fd0df2a72b5f44d3c8a2f4a0")),
                0x0503474d => NewGRFHash(hex!("2e96b9ab2bea686bff94961ad433a701")),
                0x22333232 => NewGRFHash(hex!("316180da1ba6444a06cd17f8fa79d60a")),
            }),

            game_date: DateTime::from_utc(
                NaiveDateTime::from_timestamp_opt(715875, 0).unwrap(),
                Utc,
            ),
            start_date: DateTime::from_utc(
                NaiveDateTime::from_timestamp_opt(715875, 0).unwrap(),
                Utc,
            ),

            max_companies: 15,
            current_companies: 0,
            max_spectators: 10,

            server_name: CString::new("OnlyFriends OpenTTD Server #1").unwrap(),
            map_name: CString::new("Random Map").unwrap(),
            clients_on: 0,
            clients_max: 25,
            use_password: false,
            server_revision: CString::new("1.5.3").unwrap(),
            server_lang: 22,
            spectators_on: 0,
            map_width: 1024,
            map_height: 1024,
            map_set: 1,
            dedicated: true,
        };

        (b, srv)
    }

    #[test]
    fn test_parse_server_response() {
        let (input, expectation) = fixtures();

        let result = ServerResponse::from_bytes(&input).unwrap();

        assert_eq!(expectation, result.1);
    }

    #[test]
    fn test_write_server_response() {
        let (expectation, input) = fixtures();

        let mut result = Vec::new();
        input.write_pkt(&mut result).unwrap();

        assert_eq!(expectation, result);
    }
}
