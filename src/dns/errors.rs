use std::error::Error;
use std::fmt;

use super::{DnsFlags, DnsPacket, DnsRCode};

#[derive(Debug)]
pub struct DnsFormatError {
    message: String,
    partial: Option<DnsPacket>,
}

impl DnsFormatError {
    pub fn make_error(message: String) -> DnsFormatError {
        DnsFormatError {
            message,
            partial: None,
        }
    }

    pub fn get_message(&self) -> &String {
        &self.message
    }

    // A partial packet should not contain answers, nameservers, or ARs in it,
    // even if they were in the query and successfully decoded. For now, at least;
    // TODO figure out what a DNS server does and does not send back on FormErr
    // when off this airplane
    pub fn set_partial(&mut self, packet: DnsPacket) {
        self.partial = Some(packet);
    }

    // Return a FormError response based on the partial packet we decoded
    // If we didn't get far enough in the decode process to have a partial, we
    // return nothing instead; can't find an RFC reference on this yet but
    // Google DNS does not respond in practice to requests <11 bytes (why 11
    // and not 12? I don't know yet).
    pub fn get_error_response(&self) -> Option<DnsPacket> {
        match &self.partial {
            Some(packet) => {
                let flags = DnsFlags {
                    // Set QR bit, this is a reply
                    qr_bit: true,
                    // Clear AA, TC, RA, and AD bits even if set by client, I think?
                    // TODO(dylan): Check this logic is accurate for all four of these
                    aa_bit: false,
                    tc_bit: false,
                    ra_bit: false,
                    ad_bit: false,
                    // This is a FormError
                    rcode: DnsRCode::FormError,
                    // Copy the remaining flags given to us by the client
                    ..packet.flags
                };
                Some(DnsPacket {
                    id: packet.id,
                    flags,
                    // Don't return any questions/answers/etc
                    questions: Vec::new(),
                    answers: Vec::new(),
                    nameservers: Vec::new(),
                    addl_recs: Vec::new(),
                })
            }
            None => None,
        }
    }
}

impl fmt::Display for DnsFormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DNS packet had format error: {}", self.message)
    }
}

impl Error for DnsFormatError {}
