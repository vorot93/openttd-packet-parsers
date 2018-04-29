use crate::util::*;
use byteorder::{LittleEndian, WriteBytesExt};
use nom::{self, combinator::map, number::complete::*, sequence::tuple, *};
use std::ffi::CString;

#[derive(Clone, Debug, PartialEq)]
pub struct ServerRegistrationData {
    pub welcome_message: CString,
    pub server_version: u8,
    pub port: u16,
    pub session_key: u64,
}

impl ByteWriter for ServerRegistrationData {
    fn write_pkt(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        buf.append(&mut self.welcome_message.clone().into_bytes_with_nul());
        buf.write_u8(self.server_version)?;
        buf.write_u16::<LittleEndian>(self.port)?;
        buf.write_u64::<LittleEndian>(self.session_key)?;

        Ok(())
    }
}

impl PacketPayload for ServerRegistrationData {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(
            tuple((read_cstring, le_u8, le_u16, le_u64)),
            |(welcome_message, server_version, port, session_key)| Self {
                welcome_message,
                server_version,
                port,
                session_key,
            },
        )
        .parse(input)
    }
}
