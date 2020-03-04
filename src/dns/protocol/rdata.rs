use std::net::{Ipv4Addr, Ipv6Addr};

use super::{bigendians, names, DnsFormatError, DnsRRType};

#[derive(Clone, PartialEq, Debug)]
pub enum DnsRecordData {
    A(Ipv4Addr),
    NS(Vec<String>),
    AAAA(Ipv6Addr),
    CNAME(Vec<String>),
    Other(Vec<u8>),
}

impl DnsRecordData {
    pub fn from_bytes(
        packet_bytes: &[u8],
        mut pos: usize,
        rr_type: &DnsRRType,
        rd_length: u16,
    ) -> Result<(DnsRecordData, usize), DnsFormatError> {
        let record_bytes = packet_bytes[pos..pos + (rd_length as usize)].to_vec();
        let record = match rr_type {
            DnsRRType::A => DnsRecordData::A(Ipv4Addr::new(
                record_bytes[0],
                record_bytes[1],
                record_bytes[2],
                record_bytes[3],
            )),
            DnsRRType::AAAA => DnsRecordData::AAAA(Ipv6Addr::new(
                bigendians::to_u16(&record_bytes[0..2]),
                bigendians::to_u16(&record_bytes[2..4]),
                bigendians::to_u16(&record_bytes[4..6]),
                bigendians::to_u16(&record_bytes[6..8]),
                bigendians::to_u16(&record_bytes[8..10]),
                bigendians::to_u16(&record_bytes[10..12]),
                bigendians::to_u16(&record_bytes[12..14]),
                bigendians::to_u16(&record_bytes[14..16]),
            )),
            DnsRRType::NS => {
                let (name, _) = names::deserialize_name(&packet_bytes, pos)?;
                DnsRecordData::NS(name)
            }
            DnsRRType::CNAME => {
                let (name, _) = names::deserialize_name(&packet_bytes, pos)?;
                DnsRecordData::CNAME(name)
            }
            _ => DnsRecordData::Other(record_bytes),
        };
        pos += rd_length as usize;

        Ok((record, pos))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match &self {
            DnsRecordData::A(ipv4) => ipv4.octets().to_vec(),
            DnsRecordData::AAAA(ipv6) => ipv6.octets().to_vec(),
            DnsRecordData::NS(labels) => names::serialize_name(&labels),
            DnsRecordData::CNAME(labels) => names::serialize_name(&labels),
            DnsRecordData::Other(record_bytes) => record_bytes.to_vec(),
        }
    }
}
