// Functions for handling DNS names

// Unlike the other functions, `bytes` here must be the WHOLE dns packet,
// because labels can contain pointers to back earlier in the packet.
// TODO(dylan): this feels a lot less clean and breaks the consistency of these
// private functions. I'm not sure what a good design is here yet; considered
// using a map for the label pointers but there's complications with that idea
pub fn deserialize_name(bytes: &[u8], start: usize) -> (Vec<String>, usize) {
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
pub fn serialize_name(name: &Vec<String>) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use crate::dns::names::*;

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

        let (labels, pos) = deserialize_name(&packet, 20);
        assert_eq!(labels, vec!["f", "isi", "arpa"]);
        assert_eq!(pos, 32);

        let (labels, pos) = deserialize_name(&packet, 40);
        assert_eq!(labels, vec!["foo", "f", "isi", "arpa"]);
        assert_eq!(pos, 46);

        let (labels, pos) = deserialize_name(&packet, 64);
        assert_eq!(labels, vec!["arpa"]);
        assert_eq!(pos, 66);

        let (labels, pos) = deserialize_name(&packet, 92);
        assert_eq!(labels, Vec::<String>::new());
        assert_eq!(pos, 93);
    }
}
