use super::{bigendians, names, DnsClass, DnsRRType};

#[derive(Clone, PartialEq, Debug)]
pub struct DnsResourceRecord {
    // See comment in DnsQuestion struct above, the first three fields here are
    // nearly identical
    pub name: Vec<String>,
    pub rr_type: DnsRRType,
    pub class: DnsClass,
    // Unsigned 32 bit integer signifying the amount of time the client can
    // cache this answer for. 0 means not to cache. Note that RFC 1035 states
    // this is signed in some sections, this is corrected in errata.
    pub ttl: u32,
    // Record length: tells us how long the data in record data is
    pub rd_length: u16,
    // Record data: variably interpreted depending on RR type. For now, just
    // store it as a byte vector
    pub record: Vec<u8>,
}

impl DnsResourceRecord {
    // XXX EDNS OPT records are special and for now usually cause this program to panic.
    // Specifically, OPT rewrites what the "class" field should contain; it becomes the
    // UDP payload size instead of the Class ENUM. If we try to cast it from primitive, we
    // wind up panicking (unless it's exactly 254 or 255 bytes)
    pub fn from_bytes(packet_bytes: &[u8], mut pos: usize) -> (DnsResourceRecord, usize) {
        let (name, new_pos) = names::deserialize_name(&packet_bytes, pos);
        let rrtype_num = bigendians::to_u16(&packet_bytes[new_pos..new_pos + 2]);
        let class_num = bigendians::to_u16(&packet_bytes[new_pos + 2..new_pos + 4]);
        let ttl = bigendians::to_u32(&packet_bytes[new_pos + 4..new_pos + 8]);
        let rd_length = bigendians::to_u16(&packet_bytes[new_pos + 8..new_pos + 10]);
        pos = new_pos + 10;

        let record = packet_bytes[pos..pos + (rd_length as usize)].to_vec();
        pos += rd_length as usize;

        let rr_type = num::FromPrimitive::from_u16(rrtype_num).expect("Invalid rrtype");
        let class = num::FromPrimitive::from_u16(class_num).expect("Invalid class");

        let rr = DnsResourceRecord {
            name,
            rr_type,
            class,
            ttl,
            rd_length,
            record,
        };

        (rr, pos)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.append(&mut names::serialize_name(&self.name));
        bytes.extend_from_slice(&bigendians::from_u16(self.rr_type.to_owned() as u16));
        bytes.extend_from_slice(&bigendians::from_u16(self.class.to_owned() as u16));
        bytes.extend_from_slice(&bigendians::from_u32(self.ttl));
        bytes.extend_from_slice(&bigendians::from_u16(self.rd_length));
        bytes.extend_from_slice(&self.record);

        bytes
    }
}
