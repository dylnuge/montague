mod structs;

use num;

// *** PUBLIC FUNCTIONS ***

// Converts raw bytes into a DnsPacket struct
// TODO(dylan): real errors instead of strings
pub fn deserialize_packet(packet_bytes: &[u8]) -> Result<structs::DnsPacket, String> {
    let id: u16;
    let flags: structs::DnsFlags;
    // TODO(dylan) remove default values
    let qd_count: u16;
    let an_count: u16;
    let ns_count: u16;
    let ar_count: u16;
    let mut questions: Vec<structs::DnsQuestion> = Vec::new();
    let mut answers: Vec<structs::DnsResourceRecord> = Vec::new();
    let mut nameservers: Vec<structs::DnsResourceRecord> = Vec::new();
    let mut addl_recs: Vec<structs::DnsResourceRecord> = Vec::new();

    // TODO(dylan): Error checking, e.g. DNS request too short
    // Read the first two bytes as a big-endian u16 containing transaction id
    id = big_endian_bytes_to_u16(&packet_bytes[0..2]);
    // Next two bytes are flags
    flags = deserialize_flags(&packet_bytes[2..4])?;
    // Counts are next four u16s (big-endian)
    qd_count = big_endian_bytes_to_u16(&packet_bytes[4..6]);
    an_count = big_endian_bytes_to_u16(&packet_bytes[6..8]);
    ns_count = big_endian_bytes_to_u16(&packet_bytes[8..10]);
    ar_count = big_endian_bytes_to_u16(&packet_bytes[10..12]);

    // The header was 12 bytes, we now begin reading the rest of the packet.
    // These components are variable length (thanks to how labels are encoded)
    let mut pos: usize = 12;
    for _ in 0..qd_count {
        let (qname, new_pos) = deserialize_name(&packet_bytes, pos);
        let qtype_num = big_endian_bytes_to_u16(&packet_bytes[new_pos..new_pos + 2]);
        let qclass_num = big_endian_bytes_to_u16(&packet_bytes[new_pos + 2..new_pos + 4]);
        pos = new_pos + 4;

        let qtype = num::FromPrimitive::from_u16(qtype_num).expect("Invalid qtype");
        let qclass = num::FromPrimitive::from_u16(qclass_num).expect("Invalid qclass");

        let question = structs::DnsQuestion {
            qname,
            qtype,
            qclass,
        };

        questions.push(question);
    }

    for _ in 0..an_count {
        let (rr, new_pos) = deserialize_rr(&packet_bytes, pos);
        pos = new_pos;
        answers.push(rr);
    }

    for _ in 0..ns_count {
        let (rr, new_pos) = deserialize_rr(&packet_bytes, pos);
        pos = new_pos;
        nameservers.push(rr);
    }

    for _ in 0..ar_count {
        let (rr, new_pos) = deserialize_rr(&packet_bytes, pos);
        pos = new_pos;
        addl_recs.push(rr);
    }

    Ok(structs::DnsPacket {
        id,
        flags,
        questions,
        answers,
        nameservers,
        addl_recs,
    })
}

pub fn serialize_packet(packet: &structs::DnsPacket) -> Vec<u8> {
    let mut packet_bytes = Vec::<u8>::new();
    packet_bytes.extend_from_slice(&u16_to_big_endian_bytes(packet.id));
    packet_bytes.extend_from_slice(&serialize_flags(&packet.flags));
    packet_bytes.extend_from_slice(&u16_to_big_endian_bytes(packet.questions.len() as u16));
    packet_bytes.extend_from_slice(&u16_to_big_endian_bytes(packet.answers.len() as u16));
    packet_bytes.extend_from_slice(&u16_to_big_endian_bytes(packet.nameservers.len() as u16));
    packet_bytes.extend_from_slice(&u16_to_big_endian_bytes(packet.addl_recs.len() as u16));

    for question in &packet.questions {
        packet_bytes.extend_from_slice(&serialize_question(question));
    }
    for answer in &packet.answers {
        packet_bytes.extend_from_slice(&serialize_rr(answer));
    }
    for ns_rec in &packet.nameservers {
        packet_bytes.extend_from_slice(&serialize_rr(ns_rec));
    }
    for addl_rec in &packet.addl_recs {
        packet_bytes.extend_from_slice(&serialize_rr(addl_rec));
    }

    packet_bytes
}

pub fn nx_answer_from_query(packet: &structs::DnsPacket) -> structs::DnsPacket {
    let id = packet.id;
    let flags = structs::DnsFlags {
        qr_bit: true,
        opcode: packet.flags.opcode.to_owned(),
        aa_bit: false,
        tc_bit: false,
        rd_bit: packet.flags.rd_bit,
        ra_bit: false,
        ad_bit: false,
        cd_bit: false,
        rcode: structs::DnsRCode::NXDomain,
    };

    let questions = packet.questions.to_owned();
    let answers = Vec::<structs::DnsResourceRecord>::new();
    let nameservers = Vec::<structs::DnsResourceRecord>::new();
    let addl_recs = Vec::<structs::DnsResourceRecord>::new();

    structs::DnsPacket {
        id,
        flags,
        questions,
        answers,
        nameservers,
        addl_recs,
    }
}

// *** PRIVATE FUNCTIONS ***

// Parse the next two bytes in the passed slice into a u16, assuming they're
// encoded big-endian (network byte order)
// TODO(dylan): there's probably more idiomatic ways of handling byte
// conversions in Rust. As is, this function isn't even checking if the slice
// passed to it is the right size.
fn big_endian_bytes_to_u16(bytes: &[u8]) -> u16 {
    ((bytes[0] as u16) << 8) + (bytes[1] as u16)
}

fn big_endian_bytes_to_u32(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 24)
        + ((bytes[1] as u32) << 16)
        + ((bytes[2] as u32) << 8)
        + (bytes[3] as u32)
}

fn u16_to_big_endian_bytes(num: u16) -> [u8; 2] {
    [(num >> 8 & 0xff) as u8, (num & 0xff) as u8]
}

fn u32_to_big_endian_bytes(num: u32) -> [u8; 4] {
    [
        (num >> 24 & 0xff) as u8,
        (num >> 16 & 0xff) as u8,
        (num >> 8 & 0xff) as u8,
        (num & 0xff) as u8,
    ]
}

fn deserialize_flags(bytes: &[u8]) -> Result<structs::DnsFlags, String> {
    let qr_bit: bool = (bytes[0] >> 7) & 1 == 1;
    let aa_bit: bool = (bytes[0] >> 2) & 1 == 1;
    let tc_bit: bool = (bytes[0] >> 1) & 1 == 1;
    let rd_bit: bool = (bytes[0]) & 1 == 1;
    let ra_bit: bool = (bytes[1] >> 7) & 1 == 1;
    let ad_bit: bool = (bytes[1] >> 5) & 1 == 1;
    let cd_bit: bool = (bytes[1] >> 4) & 1 == 1;

    let opcode_val: u8 = (bytes[0] >> 3) & 0b1111;
    let rcode_val: u8 = (bytes[1]) & 0b1111;

    let opcode = num::FromPrimitive::from_u8(opcode_val).expect("Invalid opcode");
    let rcode = num::FromPrimitive::from_u8(rcode_val).expect("Invalid rcode");

    Ok(structs::DnsFlags {
        qr_bit,
        opcode,
        aa_bit,
        tc_bit,
        rd_bit,
        ra_bit,
        ad_bit,
        cd_bit,
        rcode,
    })
}

fn serialize_flags(flags: &structs::DnsFlags) -> [u8; 2] {
    let mut flag_bytes = [0x00, 0x00];
    // Could also just convert bools to 1/0, shift them, and OR them, but this
    // avoids the type conversion and IMHO looks a little cleaner (albeit verbose)
    if flags.qr_bit {
        flag_bytes[0] |= 0b10000000;
    }
    if flags.aa_bit {
        flag_bytes[0] |= 0b00000100;
    }
    if flags.tc_bit {
        flag_bytes[0] |= 0b00000010;
    }
    if flags.rd_bit {
        flag_bytes[0] |= 0b00000001;
    }
    if flags.ra_bit {
        flag_bytes[1] |= 0b10000000;
    }
    if flags.ad_bit {
        flag_bytes[1] |= 0b00100000;
    }
    if flags.cd_bit {
        flag_bytes[1] |= 0b00010000;
    }

    // TODO(dylan): The need to copy the enums here just to get their int value
    // feels like it might be wrong; there's probably a better way to do this.
    // Clear out all but the lower four bits to ensure this won't clobber other fields.
    let opcode_num = (flags.opcode.to_owned() as u8) & 0x0f;
    let rcode_num = (flags.rcode.to_owned() as u8) & 0x0f;
    flag_bytes[0] |= opcode_num << 3;
    flag_bytes[1] |= rcode_num;

    flag_bytes
}

// XXX EDNS OPT records are special and for now usually cause this program to panic.
// Specifically, OPT rewrites what the "class" field should contain; it becomes the
// UDP payload size instead of the Class ENUM. If we try to cast it from primitive, we
// wind up panicking (unless it's exactly 254 or 255 bytes)
fn deserialize_rr(packet_bytes: &[u8], mut pos: usize) -> (structs::DnsResourceRecord, usize) {
    let (name, new_pos) = deserialize_name(&packet_bytes, pos);
    let rrtype_num = big_endian_bytes_to_u16(&packet_bytes[new_pos..new_pos + 2]);
    let class_num = big_endian_bytes_to_u16(&packet_bytes[new_pos + 2..new_pos + 4]);
    let ttl = big_endian_bytes_to_u32(&packet_bytes[new_pos + 4..new_pos + 8]);
    let rd_length = big_endian_bytes_to_u16(&packet_bytes[new_pos + 8..new_pos + 10]);
    pos = new_pos + 10;

    let record = packet_bytes[pos..pos + (rd_length as usize)].to_vec();
    pos += rd_length as usize;

    let rr_type = num::FromPrimitive::from_u16(rrtype_num).expect("Invalid rrtype");
    let class = num::FromPrimitive::from_u16(class_num).expect("Invalid class");

    let rr = structs::DnsResourceRecord {
        name,
        rr_type,
        class,
        ttl,
        rd_length,
        record,
    };

    (rr, pos)
}

fn serialize_question(question: &structs::DnsQuestion) -> Vec<u8> {
    let mut bytes = Vec::new();

    bytes.append(&mut serialize_name(&question.qname));
    bytes.extend_from_slice(&u16_to_big_endian_bytes(question.qtype.to_owned() as u16));
    bytes.extend_from_slice(&u16_to_big_endian_bytes(question.qclass.to_owned() as u16));

    bytes
}

fn serialize_rr(record: &structs::DnsResourceRecord) -> Vec<u8> {
    let mut bytes = Vec::new();

    bytes.append(&mut serialize_name(&record.name));
    bytes.extend_from_slice(&u16_to_big_endian_bytes(record.rr_type.to_owned() as u16));
    bytes.extend_from_slice(&u16_to_big_endian_bytes(record.class.to_owned() as u16));
    bytes.extend_from_slice(&u32_to_big_endian_bytes(record.ttl));
    bytes.extend_from_slice(&u16_to_big_endian_bytes(record.rd_length));
    bytes.extend_from_slice(&record.record);

    bytes
}

// Unlike the other functions, `bytes` here must be the WHOLE dns packet,
// because labels can contain pointers to back earlier in the packet.
// TODO(dylan): this feels a lot less clean and breaks the consistency of these
// private functions. I'm not sure what a good design is here yet; considered
// using a map for the label pointers but there's complications with that idea
fn deserialize_name(bytes: &[u8], start: usize) -> (Vec<String>, usize) {
    // TODO: This function doesn't handle malformed packets yet
    let mut labels = Vec::new();
    let mut pos = start;
    loop {
        let len_byte = bytes[pos];
        // If the length begins with the bits 11, it is a pointer
        // If it begins with the bits 00, it is a length
        // Otherwise, it is invalid
        match (len_byte >> 6) & 0b11u8 {
            0b11 => {
                // The pointer includes the lower 6 bits of the "length" and
                // the entirety of the next byte
                let pointer_start: usize =
                    (((len_byte & 0b111111u8) as usize) << 8) + (bytes[pos + 1] as usize);

                // We don't care where the other name ends, just what is there
                let (mut remainder, _) = deserialize_name(bytes, pointer_start);
                labels.append(&mut remainder);

                // A pointer always is the end of a label; we can advance the
                // position by the two bytes we've read and return.
                pos += 2;
                break;
            }
            0b00 => {
                // Read the next `len_byte` bytes as a label
                let length = len_byte as usize;
                pos += 1;
                if length == 0 {
                    // When we reach a label of length zero, we're done reading
                    // the name
                    break;
                }
                // TODO the spec is kind of annoying here. It talks a lot about
                // ASCII but doesn't ever require a domain is made of only ASCII
                // characters. Further, it talks about "case insensitivity" but
                // then seems to suggest that if any byte is not alphanumeric
                // ASCII that's out the window. Let's treat it as a case
                // sensitive UTF-8 string for now.
                let label = String::from_utf8(bytes[pos..pos + length].to_vec())
                    .expect("Label was not UTF-8");
                labels.push(label);
                pos += length;
            }
            _ => {
                // TODO ERROR HANDLING
                break;
            }
        }
    }
    (labels, pos)
}

// This serialize doesn't take possible label compression into account
// It also assumes its input will not have any labels > 63 characters long
fn serialize_name(name: &Vec<String>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in name {
        // First byte is label length
        let len: u8 = label.len() as u8;
        bytes.push(len);
        for byte in label.as_bytes() {
            bytes.push(*byte);
        }
    }
    // End with the null label
    bytes.push(0x00);

    bytes
}

// *** TESTS ***

#[cfg(test)]
mod tests {
    use crate::dns;

    #[test]
    fn u16_parse_works() {
        assert_eq!(66, dns::big_endian_bytes_to_u16(&[0x00u8, 0x42u8]));
        assert_eq!(6025, dns::big_endian_bytes_to_u16(&[0x17u8, 0x89u8]));
        assert_eq!(32902, dns::big_endian_bytes_to_u16(&[0x80u8, 0x86u8]));
        // Ensure additional bytes are irrelevant
        assert_eq!(
            32902,
            dns::big_endian_bytes_to_u16(&[0x80u8, 0x86u8, 0x00u8])
        );
    }

    #[test]
    fn u32_parse_works() {
        assert_eq!(
            32902,
            dns::big_endian_bytes_to_u32(&[0x00u8, 0x00u8, 0x80u8, 0x86u8])
        );
        assert_eq!(
            537034886,
            dns::big_endian_bytes_to_u32(&[0x20u8, 0x02u8, 0x80u8, 0x86u8])
        );
    }

    #[test]
    fn u16_serialize_works() {
        assert_eq!([0x00u8, 0x42u8], dns::u16_to_big_endian_bytes(66));
        assert_eq!([0x17u8, 0x89u8], dns::u16_to_big_endian_bytes(6025));
        assert_eq!([0x80u8, 0x86u8], dns::u16_to_big_endian_bytes(32902));
    }

    #[test]
    fn u32_serialize_works() {
        assert_eq!(
            [0x00u8, 0x00u8, 0x80u8, 0x86u8],
            dns::u32_to_big_endian_bytes(32902)
        );
        assert_eq!(
            [0x20u8, 0x02u8, 0x80u8, 0x86u8],
            dns::u32_to_big_endian_bytes(537034886)
        );
    }

    #[test]
    fn flags_deserialize_works() {
        let flag_bytes = [0x01u8, 0x20u8];
        let expected = dns::structs::DnsFlags {
            qr_bit: false,
            opcode: dns::structs::DnsOpcode::Query,
            aa_bit: false,
            tc_bit: false,
            rd_bit: true,
            ra_bit: false,
            ad_bit: true,
            cd_bit: false,
            rcode: dns::structs::DnsRCode::NoError,
        };
        let result = dns::deserialize_flags(&flag_bytes).expect("Unexpected error");
        assert_eq!(expected, result);

        let flag_bytes = [0xacu8, 0x23u8];
        let expected = dns::structs::DnsFlags {
            qr_bit: true,
            opcode: dns::structs::DnsOpcode::Update,
            aa_bit: true,
            tc_bit: false,
            rd_bit: false,
            ra_bit: false,
            ad_bit: true,
            cd_bit: false,
            rcode: dns::structs::DnsRCode::NXDomain,
        };
        let result = dns::deserialize_flags(&flag_bytes).expect("Unexpected error");
        assert_eq!(expected, result);
    }

    #[test]
    fn name_read_works() {
        // Using the example in RFC1035 to demonstrate both my code works how I
        // think it does and my comprehension of how it's supposed to work.

        // Initalize our example "packet" with 0x00s. We don't care about the
        // values outside where our labels live.
        let mut packet = [0x00u8; 93];
        // First label starting at byte 20 is f.isi.arpa
        packet[20] = 1;
        packet[21] = 'f' as u8;
        packet[22] = 3;
        packet[23] = 'i' as u8;
        packet[24] = 's' as u8;
        packet[25] = 'i' as u8;
        packet[26] = 4;
        packet[27] = 'a' as u8;
        packet[28] = 'r' as u8;
        packet[29] = 'p' as u8;
        packet[30] = 'a' as u8;
        packet[31] = 0;

        // Second label starting at byte 40 is foo.f.isi.arpa
        packet[40] = 3;
        packet[41] = 'f' as u8;
        packet[42] = 'o' as u8;
        packet[43] = 'o' as u8;
        // Pointer to "f.isi.arpa" at byte 20
        packet[44] = 0b11000000;
        packet[45] = 20;

        // Third label at byte 64 is .arpa, pointer to byte 26
        packet[64] = 0b11000000;
        packet[65] = 26;

        // Fourth label at byte 92 is just the root
        packet[92] = 0;

        let (labels, pos) = dns::deserialize_name(&packet, 20);
        assert_eq!(labels, vec!["f", "isi", "arpa"]);
        assert_eq!(pos, 32);

        let (labels, pos) = dns::deserialize_name(&packet, 40);
        assert_eq!(labels, vec!["foo", "f", "isi", "arpa"]);
        assert_eq!(pos, 46);

        let (labels, pos) = dns::deserialize_name(&packet, 64);
        assert_eq!(labels, vec!["arpa"]);
        assert_eq!(pos, 66);

        let (labels, pos) = dns::deserialize_name(&packet, 92);
        assert_eq!(labels, Vec::<String>::new());
        assert_eq!(pos, 93);
    }
}
