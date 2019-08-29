// Parse the next two bytes in the passed slice into a u16, assuming they're
// encoded big-endian (network byte order)
// TODO(dylan): there's probably more idiomatic ways of handling byte
// conversions in Rust. As is, this function isn't even checking if the slice
// passed to it is the right size.
pub fn to_u16(bytes: &[u8]) -> u16 {
    ((bytes[0] as u16) << 8) + (bytes[1] as u16)
}

pub fn to_u32(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 24)
        + ((bytes[1] as u32) << 16)
        + ((bytes[2] as u32) << 8)
        + (bytes[3] as u32)
}

pub fn from_u16(num: u16) -> [u8; 2] {
    [(num >> 8 & 0xff) as u8, (num & 0xff) as u8]
}

pub fn from_u32(num: u32) -> [u8; 4] {
    [
        (num >> 24 & 0xff) as u8,
        (num >> 16 & 0xff) as u8,
        (num >> 8 & 0xff) as u8,
        (num & 0xff) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use crate::dns::bigendians::*;

    #[test]
    fn u16_parse_works() {
        assert_eq!(66, to_u16(&[0x00u8, 0x42u8]));
        assert_eq!(6025, to_u16(&[0x17u8, 0x89u8]));
        assert_eq!(32902, to_u16(&[0x80u8, 0x86u8]));
        // Ensure additional bytes are irrelevant
        assert_eq!(32902, to_u16(&[0x80u8, 0x86u8, 0x00u8]));
    }

    #[test]
    fn u32_parse_works() {
        assert_eq!(32902, to_u32(&[0x00u8, 0x00u8, 0x80u8, 0x86u8]));
        assert_eq!(537034886, to_u32(&[0x20u8, 0x02u8, 0x80u8, 0x86u8]));
    }

    #[test]
    fn u16_serialize_works() {
        assert_eq!([0x00u8, 0x42u8], from_u16(66));
        assert_eq!([0x17u8, 0x89u8], from_u16(6025));
        assert_eq!([0x80u8, 0x86u8], from_u16(32902));
    }

    #[test]
    fn u32_serialize_works() {
        assert_eq!([0x00u8, 0x00u8, 0x80u8, 0x86u8], from_u32(32902));
        assert_eq!([0x20u8, 0x02u8, 0x80u8, 0x86u8], from_u32(537034886));
    }
}
