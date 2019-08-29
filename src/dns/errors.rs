use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub struct DnsFormatError {
    pub message: String,
}

impl fmt::Display for DnsFormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DNS packet had format error: {}", self.message)
    }
}

impl Error for DnsFormatError {
}
