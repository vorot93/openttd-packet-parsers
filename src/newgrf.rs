use crate::util::*;
use nom::{
    self,
    bytes::complete::take,
    combinator::map,
    multi::count,
    number::complete::*,
    sequence::{tuple, Tuple},
    *,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fmt,
};
use strum::EnumDiscriminants;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NewGRFHash(pub [u8; 16]);

impl fmt::Display for NewGRFHash {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        for byte in self.0.iter() {
            write!(fmt, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, EnumDiscriminants)]
#[strum_discriminants(repr(u8))]
#[strum_discriminants(derive(IntoPrimitive, TryFromPrimitive))]
pub enum ActiveNewGrf {
    OnlyId(BTreeMap<u32, NewGRFHash>),
    Full(BTreeMap<u32, (NewGRFHash, CString)>),
    Lookup(BTreeSet<u32>),
}

pub fn newgrf_md5(input: &[u8]) -> IResult<&[u8], NewGRFHash> {
    map(take(16_usize), |v| {
        let mut out = [0; 16];
        out.copy_from_slice(v);
        NewGRFHash(out)
    })
    .parse(input)
}

pub fn newgrf_entry(input: &[u8]) -> IResult<&[u8], (u32, NewGRFHash)> {
    (le_u32, newgrf_md5).parse(input)
}

pub fn newgrf_entry_full(input: &[u8]) -> IResult<&[u8], (u32, (NewGRFHash, CString))> {
    map(tuple((newgrf_entry, read_cstring)), |((id, hash), name)| {
        (id, (hash, name))
    })
    .parse(input)
}

impl ActiveNewGrf {
    pub fn from_bytes(input: &[u8], kind: ActiveNewGrfDiscriminants) -> IResult<&[u8], Self> {
        let (input, active_newgrf_num) = map(le_u8, usize::from).parse(input)?;

        match kind {
            ActiveNewGrfDiscriminants::Full => {
                map(count(newgrf_entry_full, active_newgrf_num), |newgrf_data| {
                    Self::Full(newgrf_data.into_iter().collect())
                })
                .parse(input)
            }
            ActiveNewGrfDiscriminants::OnlyId => {
                map(count(newgrf_entry, active_newgrf_num), |newgrf_data| {
                    Self::OnlyId(newgrf_data.into_iter().collect())
                })
                .parse(input)
            }
            ActiveNewGrfDiscriminants::Lookup => {
                map(count(le_u32, active_newgrf_num), |newgrf_data| {
                    Self::Lookup(newgrf_data.into_iter().collect())
                })
                .parse(input)
            }
        }
    }
}
