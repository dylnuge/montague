// Recursive resolver functionality

mod root;

use std::error;
use std::net::{IpAddr, UdpSocket};

use super::protocol::{
    DnsFlags, DnsFormatError, DnsOpcode, DnsPacket, DnsQuestion, DnsRCode, DnsResourceRecord,
};

// Right now this doesn't use caching, etc
pub fn resolve_question(question: DnsQuestion) -> Result<Vec<DnsResourceRecord>, DnsFormatError> {
    Ok(vec![])
}

fn query_nameserver(question: DnsQuestion, ns: IpAddr) -> Result<DnsPacket, Box<dyn error::Error>> {
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
        questions: vec![question],
        answers: vec![],
        nameservers: vec![],
        addl_recs: vec![],
    };

    // Send the query
    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind");
    socket.connect((ns, 53)).expect("couldn't connect");
    socket.send(&packet.to_bytes()).expect("couldn't send");
    let mut buf = [0; 2048];
    let amt = socket.recv(&mut buf).expect("didn't get reply");

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
        let packet = query_nameserver(question, ns).expect("query should have worked");
        println!("{:?}", packet);
    }
}
