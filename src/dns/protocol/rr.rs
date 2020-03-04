use super::{bigendians, names, DnsClass, DnsFormatError, DnsRRType, RecordData};

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

        let (record, pos) = RecordData::from_bytes(packet_bytes, pos, &rr_type, rd_length)?;
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
        let record = &self.record.to_bytes();

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
}
