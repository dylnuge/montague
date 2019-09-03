use super::{DnsFormatError, DnsOpcode, DnsRCode};

#[derive(Clone, PartialEq, Debug)]
pub struct DnsFlags {
    // Query/Response: True if this is a response, false if it is a query
    pub qr_bit: bool,
    // Opcode: A four bit field indicating the DNS operation being performed
    pub opcode: DnsOpcode,
    // Authoritative Answer: True if this is a response from the server that
    // is the authority for the domain being queried, false otherwise.
    pub aa_bit: bool,
    // TrunCation: True if the message was truncated for being too long
    pub tc_bit: bool,
    // Recursion Desired: True if query wants nameserver to resolve this
    // request recursively, false if not. Copied into the response.
    pub rd_bit: bool,
    // Recursion Available: True if this is a response from a server that
    // supports recursion, false if response is from a server that does not,
    // undefined/ignored in a query
    pub ra_bit: bool,
    // The next bit is the Z field, which is reserved and should be zero. We
    // don't need it in the struct

    // TODO(dylan): Better understand/document next two DNSSEC flags
    // Authenticated Data: Part of DNSSEC (RFC 2535, 4035 and others). Indicates
    // that DNSSEC was used to authenticate all responses. Only relevant when
    // communicating with trusted nameservers.
    pub ad_bit: bool,
    // Checking Disabled: Also DNSSEC (RFC 2535, 4035 and others). Indicates
    // DNSSEC should not be used/was not used in serving this response
    pub cd_bit: bool,
    // RCode: A four bit field indicating the status of a response.
    // Undefined/ignored in queries.
    pub rcode: DnsRCode,
}

impl DnsFlags {
    pub fn from_bytes(bytes: &[u8]) -> Result<DnsFlags, DnsFormatError> {
        let qr_bit: bool = (bytes[0] >> 7) & 1 == 1;
        let aa_bit: bool = (bytes[0] >> 2) & 1 == 1;
        let tc_bit: bool = (bytes[0] >> 1) & 1 == 1;
        let rd_bit: bool = (bytes[0]) & 1 == 1;
        let ra_bit: bool = (bytes[1] >> 7) & 1 == 1;
        let z_bit: bool = (bytes[1] >> 6) & 1 == 1;
        let ad_bit: bool = (bytes[1] >> 5) & 1 == 1;
        let cd_bit: bool = (bytes[1] >> 4) & 1 == 1;

        if z_bit {
            return Err(DnsFormatError::make_error(format!("Z bit was set")));
        }

        let opcode_val: u8 = (bytes[0] >> 3) & 0b1111;
        let rcode_val: u8 = (bytes[1]) & 0b1111;

        let opcode = match num::FromPrimitive::from_u8(opcode_val) {
            Some(x) => Ok(x),
            None => Err(DnsFormatError::make_error(format!(
                "Invalid opcode value: {:x}",
                opcode_val
            ))),
        }?;
        let rcode = match num::FromPrimitive::from_u8(rcode_val) {
            Some(x) => Ok(x),
            None => Err(DnsFormatError::make_error(format!(
                "Invalid rcode value: {:x}",
                rcode_val
            ))),
        }?;

        Ok(DnsFlags {
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

    pub fn to_bytes(&self) -> [u8; 2] {
        let mut flag_bytes = [0x00, 0x00];
        // Could also just convert bools to 1/0, shift them, and OR them, but this
        // avoids the type conversion and IMHO looks a little cleaner (albeit verbose)
        if self.qr_bit {
            flag_bytes[0] |= 0b10000000;
        }
        if self.aa_bit {
            flag_bytes[0] |= 0b00000100;
        }
        if self.tc_bit {
            flag_bytes[0] |= 0b00000010;
        }
        if self.rd_bit {
            flag_bytes[0] |= 0b00000001;
        }
        if self.ra_bit {
            flag_bytes[1] |= 0b10000000;
        }
        if self.ad_bit {
            flag_bytes[1] |= 0b00100000;
        }
        if self.cd_bit {
            flag_bytes[1] |= 0b00010000;
        }

        // TODO(dylan): The need to copy the enums here just to get their int value
        // feels like it might be wrong; there's probably a better way to do this.
        // Clear out all but the lower four bits to ensure this won't clobber other fields.
        let opcode_num = (self.opcode.to_owned() as u8) & 0x0f;
        let rcode_num = (self.rcode.to_owned() as u8) & 0x0f;
        flag_bytes[0] |= opcode_num << 3;
        flag_bytes[1] |= rcode_num;

        flag_bytes
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::protocol::flags::*;
    use crate::dns::protocol::*;

    #[test]
    fn flags_deserialize_works() {
        let flag_bytes = [0x01u8, 0x20u8];
        let expected = DnsFlags {
            qr_bit: false,
            opcode: DnsOpcode::Query,
            aa_bit: false,
            tc_bit: false,
            rd_bit: true,
            ra_bit: false,
            ad_bit: true,
            cd_bit: false,
            rcode: DnsRCode::NoError,
        };
        let result = DnsFlags::from_bytes(&flag_bytes).expect("Unexpected error");
        assert_eq!(expected, result);

        let flag_bytes = [0xacu8, 0x23u8];
        let expected = DnsFlags {
            qr_bit: true,
            opcode: DnsOpcode::Update,
            aa_bit: true,
            tc_bit: false,
            rd_bit: false,
            ra_bit: false,
            ad_bit: true,
            cd_bit: false,
            rcode: DnsRCode::NXDomain,
        };
        let result = DnsFlags::from_bytes(&flag_bytes).expect("Unexpected error");
        assert_eq!(expected, result);
    }
}
