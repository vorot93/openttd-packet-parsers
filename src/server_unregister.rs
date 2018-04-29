use crate::util::*;
use byteorder::{LittleEndian, WriteBytesExt};
use nom::{self, combinator::map, number::complete::*, sequence::tuple, *};

#[derive(Clone, Debug, PartialEq)]
pub struct ServerUnregisterData {
    pub master_server_version: u8,
    pub port: u16,
}

impl ByteWriter for ServerUnregisterData {
    fn write_pkt(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        buf.write_u8(self.master_server_version)?;
        buf.write_u16::<LittleEndian>(self.port)?;

        Ok(())
    }
}

impl PacketPayload for ServerUnregisterData {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(tuple((le_u8, le_u16)), |(master_server_version, port)| {
            Self {
                master_server_version,
                port,
            }
        })
        .parse(input)
    }
}
