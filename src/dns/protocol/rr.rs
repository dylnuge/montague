use std::net::{Ipv4Addr, Ipv6Addr};

use super::{bigendians, names, DnsClass, DnsFormatError, DnsRRType};

#[derive(Clone, PartialEq, Debug)]
pub struct DnsResourceRecord {
    // See comment in DnsQuestion struct: the first three fields here are
    // nearly identical
    pub name: Vec<String>,
    pub rr_type: DnsRRType,
    pub class: DnsClass,
    // Unsigned 32 bit integer signifying the amount of time the client can
    // cache this answer for. 0 means not to cache. Note that RFC 1035 states
    // this is signed in some sections, this is corrected in errata.
    pub ttl: u32,
    // Record length: tells us how long the data in record data is
    // TODO: Remove this from the packet; it's not always correct to store in memory (e.g. RRs that
    // contain labels might have a different length when re-serialized based on label compression),
    // and beyond that, it should be computable from or stored with the RecordData. Leaving right
    // now because RecordData is still woefully incomplete.
    pub rd_length: u16,
    // Record data: variably interpreted depending on RR type. For now, just
    // store it as a byte vector
    pub record: RecordData,
}

#[derive(Clone, PartialEq, Debug)]
pub enum RecordData {
    A(Ipv4Addr),
    NS(Vec<String>),
    AAAA(Ipv6Addr),
    Other(Vec<u8>),
}

impl DnsResourceRecord {
    pub fn from_bytes(
        packet_bytes: &[u8],
        mut pos: usize,
    ) -> Result<(DnsResourceRecord, usize), DnsFormatError> {
        let (name, new_pos) = names::deserialize_name(&packet_bytes, pos)?;
        if new_pos + 10 > packet_bytes.len() {
            return Err(DnsFormatError::make_error(format!(
                "End of packet parsing resource record"
            )));
        }
        let rrtype_num = bigendians::to_u16(&packet_bytes[new_pos..new_pos + 2]);
        let class_num = bigendians::to_u16(&packet_bytes[new_pos + 2..new_pos + 4]);
        let ttl = bigendians::to_u32(&packet_bytes[new_pos + 4..new_pos + 8]);
        let rd_length = bigendians::to_u16(&packet_bytes[new_pos + 8..new_pos + 10]);
        pos = new_pos + 10;

        let rr_type = match num::FromPrimitive::from_u16(rrtype_num) {
            Some(x) => Ok(x),
            None => Err(DnsFormatError::make_error(format!(
                "Invalid rrtype value: {:x}",
                rrtype_num
            ))),
        }?;

        let class = if rr_type == DnsRRType::OPT {
            DnsClass::EdnsPayloadSize(class_num)
        } else {
            match DnsClass::from_u16(class_num) {
                Some(x) => Ok(x),
                None => Err(DnsFormatError::make_error(format!(
                    "Invalid class value: {:x}",
                    class_num
                ))),
            }?
        };

        let record_bytes = packet_bytes[pos..pos + (rd_length as usize)].to_vec();
        // TODO(dylan): error handling, decomposition
        let record = match rr_type {
            DnsRRType::A => RecordData::A(Ipv4Addr::new(
                record_bytes[0],
                record_bytes[1],
                record_bytes[2],
                record_bytes[3],
            )),
            DnsRRType::AAAA => RecordData::AAAA(Ipv6Addr::new(
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
                RecordData::NS(name)
            }
            _ => RecordData::Other(record_bytes),
        };
        pos += rd_length as usize;

        let rr = DnsResourceRecord {
            name,
            rr_type,
            class,
            ttl,
            rd_length,
            record,
        };

        Ok((rr, pos))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Some of these copies feel unnecessary; the issue is that though a RR object already has
        // the exact bytes for, say, an A record, it doesn't for records which contain a DNS name.
        // One option would be to _special case_ those records; i.e. detect if we're in a "just use
        // a reference" case and only alloc/copy data here if we need to. I'm not convinced the
        // complexity of the code would be worth saving, like, one 16 byte copy per AAAA record.
        let record: Vec<u8> = match &self.record {
            RecordData::A(ipv4) => ipv4.octets().to_vec(),
            RecordData::AAAA(ipv6) => ipv6.octets().to_vec(),
            RecordData::NS(labels) => names::serialize_name(&labels),
            RecordData::Other(record_bytes) => record_bytes.to_vec(),
        };

        // Bounds check that the record isn't too large to fit in a u16.
        let record_length = if record.len() <= std::u16::MAX as usize {
            record.len() as u16
        } else {
            // There's not a way for our server to _receive_ a record this large, but this isn't
            // theoretically impossible to happen; if we got a record that contained a very long
            // DNS name, but was shorter because of label compression, we might "wind up" with a
            // super long one. Of course, that would already be well beyond the name length limits
            // in RFC 1035, which limit a name to 255 bytes, but "malicious authority input causes
            // this panic" is not, like, totally impossible.
            panic!("ResourceRecord of size {} is too large to be transmitted. This is almost certainly an error with this server and not the record.", record.len());
        };

        let mut bytes = Vec::new();
        bytes.append(&mut names::serialize_name(&self.name));
        bytes.extend_from_slice(&bigendians::from_u16(self.rr_type.to_owned() as u16));
        bytes.extend_from_slice(&bigendians::from_u16(self.class.to_u16()));
        bytes.extend_from_slice(&bigendians::from_u32(self.ttl));
        bytes.extend_from_slice(&bigendians::from_u16(record_length));
        bytes.extend_from_slice(&record);
        bytes
    }

    // TODO this is not the final way I want to structure this, getters for every component of
    // every DNS record type in this class seems unwieldy
    pub fn get_a_ip(&self) -> Ipv4Addr {
        if self.rr_type != DnsRRType::A {
            panic!(
                "Attempted to decode A record on invalid rr_type {:?}",
                self.rr_type
            )
        }

        if self.rd_length != 4 {
            // Um, wat? Can this even happen? Is this check needed?
            panic!("A record contains data that is definitely not an IPv4 address");
        }

        match self.record {
            RecordData::A(ipv4) => ipv4,
            _ => panic!("A record has bad record data, somehow"),
        }
    }
}
