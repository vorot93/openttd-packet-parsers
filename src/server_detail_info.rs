use crate::util::*;
use byteorder::{LittleEndian, WriteBytesExt};
use enum_map::{enum_map, Enum, EnumMap};
use nom::{
    self,
    combinator::map,
    multi::count,
    number::complete::*,
    sequence::{tuple, Tuple},
    *,
};
use std::ffi::CString;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Enum)]
pub enum NetworkVehicleType {
    Train,
    Lorry,
    Bus,
    Plane,
    Ship,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CompanyInfo {
    pub index: u8,
    pub name: CString,
    pub inaugurated_year: u32,
    pub company_value: u64,
    pub money: u64,
    pub income: u64,
    pub performance_history: u16,
    pub has_password: bool,
    pub num_vehicles: EnumMap<NetworkVehicleType, u16>,
    pub num_stations: EnumMap<NetworkVehicleType, u16>,
    pub is_ai: bool,
}

impl ByteWriter for CompanyInfo {
    fn write_pkt(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        buf.write_u8(self.index)?;
        buf.append(&mut self.name.clone().into_bytes_with_nul());
        buf.write_u32::<LittleEndian>(self.inaugurated_year)?;
        buf.write_u64::<LittleEndian>(self.company_value)?;
        buf.write_u64::<LittleEndian>(self.money)?;
        buf.write_u64::<LittleEndian>(self.income)?;
        buf.write_u16::<LittleEndian>(self.performance_history)?;
        buf.write_u8(if self.has_password { 1 } else { 0 })?;

        for coll in [&self.num_vehicles, &self.num_stations] {
            for &v in coll.values() {
                buf.write_u16::<LittleEndian>(v)?;
            }
        }

        buf.write_u8(if self.is_ai { 1 } else { 0 })?;

        Ok(())
    }
}

pub fn parse_company_info(input: &[u8]) -> IResult<&[u8], CompanyInfo> {
    map(
        tuple((
            le_u8,
            read_cstring,
            le_u32,
            le_u64,
            le_u64,
            le_u64,
            le_u16,
            map(le_u8, |v| v > 0),
            le_u16,
            le_u16,
            le_u16,
            le_u16,
            le_u16,
            le_u16,
            le_u16,
            le_u16,
            le_u16,
            le_u16,
            map(le_u8, |v| v > 0),
        )),
        |(
            index,
            name,
            inaugurated_year,
            company_value,
            money,
            income,
            performance_history,
            has_password,
            num_vehicles_train,
            num_vehicles_lorry,
            num_vehicles_bus,
            num_vehicles_plane,
            num_vehicles_ship,
            num_stations_train,
            num_stations_lorry,
            num_stations_bus,
            num_stations_plane,
            num_stations_ship,
            is_ai,
        )| CompanyInfo {
            index,
            name,
            inaugurated_year,
            company_value,
            money,
            income,
            performance_history,
            has_password,
            num_vehicles: enum_map! {
                NetworkVehicleType::Train => num_vehicles_train,
                NetworkVehicleType::Lorry => num_vehicles_lorry,
                NetworkVehicleType::Bus => num_vehicles_bus,
                NetworkVehicleType::Plane => num_vehicles_plane,
                NetworkVehicleType::Ship => num_vehicles_ship,
            },
            num_stations: enum_map! {
                NetworkVehicleType::Train => num_stations_train,
                NetworkVehicleType::Lorry => num_stations_lorry,
                NetworkVehicleType::Bus => num_stations_bus,
                NetworkVehicleType::Plane => num_stations_plane,
                NetworkVehicleType::Ship => num_stations_ship,
            },
            is_ai,
        },
    )
    .parse(input)
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerDetailInfo {
    pub company_info_version: u8,
    pub companies: Vec<CompanyInfo>,
}

impl ByteWriter for ServerDetailInfo {
    fn write_pkt(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        buf.write_u8(self.company_info_version)?;
        buf.write_u8(self.companies.len() as u8)?;
        for company in self.companies.iter() {
            company.write_pkt(buf)?;
        }

        Ok(())
    }
}

impl PacketPayload for ServerDetailInfo {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (company_info_version, company_count)) = (le_u8, le_u8).parse(input)?;

        map(
            count(parse_company_info, company_count as usize),
            move |companies| Self {
                company_info_version,
                companies,
            },
        )
        .parse(input)
    }
}
