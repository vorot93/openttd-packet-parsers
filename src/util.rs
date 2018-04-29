use chrono::prelude::*;
use nom::{
    bytes::complete::{take, take_till},
    combinator::map_res,
    IResult, Parser,
};
use std::ffi::CString;

pub fn read_cstring(input: &[u8]) -> IResult<&[u8], CString> {
    let (input, s) = map_res(take_till(|v| v == 0), CString::new).parse(input)?;
    let (input, _) = take(1_usize).parse(input)?;
    Ok((input, s))
}

pub fn datetime_from_ts<T: Into<i64>>(ts: T) -> DateTime<Utc> {
    DateTime::from_utc(
        NaiveDateTime::from_timestamp_opt(ts.into(), 0).unwrap(),
        Utc,
    )
}

pub trait ByteWriter {
    /// Encode self and write bytes into buffer
    fn write_pkt(&self, out: &mut Vec<u8>) -> std::io::Result<()>;
}

pub trait PacketPayload: ByteWriter {
    /// Decode self from bytes
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized;
}
