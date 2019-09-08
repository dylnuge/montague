// Recursive resolver functionality

mod root;

use std::error::Error;
use std::net::{IpAddr, UdpSocket};

use super::protocol::{
    DnsFlags, DnsFormatError, DnsOpcode, DnsPacket, DnsQuestion, DnsRCode, DnsResourceRecord,
};

// Right now this doesn't use caching, etc
pub fn resolve_question(question: &DnsQuestion) -> Result<DnsPacket, Box<dyn Error>> {
    // Query the root nameserver
    let ns = root::get_root_nameserver();
    let response = query_nameserver(question, ns)?;
    Ok(response)
}

// Sends a query to an authoritative nameserver
fn query_nameserver(question: &DnsQuestion, ns: IpAddr) -> Result<DnsPacket, Box<dyn Error>> {
    // Construct the query
    let flags = DnsFlags {
        qr_bit: false,
        opcode: DnsOpcode::Query,
        aa_bit: false,
        tc_bit: false,
        rd_bit: false,
        ra_bit: false,
        ad_bit: false,
        cd_bit: false,
        rcode: DnsRCode::NoError,
    };
    let packet = DnsPacket {
        // TODO real arbitrary ID instead of just hardcoded one
        id: 42,
        flags,
        // TODO is copying the question the right thing to do here? We don't _really_ need another
        // object, we could potentially refactor packet to write bytes from references. qname is a
        // string vector, so this is a non-trivial copy.
        questions: vec![question.to_owned()],
        answers: vec![],
        nameservers: vec![],
        addl_recs: vec![],
    };

    // Send the query
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect((ns, 53))?;
    socket.send(&packet.to_bytes())?;
    let mut buf = [0; 2048];
    let amt = socket.recv(&mut buf)?;

    // Process the reply
    let reply = DnsPacket::from_bytes(&buf[..amt])?;

    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};

    use crate::dns::protocol;

    #[test]
    fn test_ns_query() {
        let question = protocol::DnsQuestion {
            qname: vec!["google".to_owned(), "com".to_owned()],
            qtype: protocol::DnsRRType::A,
            qclass: protocol::DnsClass::IN,
        };
        let ns = IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10));
        let packet = query_nameserver(&question, ns).expect("query should have worked");
        println!("{:?}", packet);
    }
}
