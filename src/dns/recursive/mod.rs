// Recursive resolver functionality

mod root;

use std::error::Error;
use std::net::{IpAddr, UdpSocket};

use super::protocol::{DnsFlags, DnsOpcode, DnsPacket, DnsQuestion, DnsRCode, DnsRRType};

// Right now this doesn't use caching, etc
pub fn resolve_question(question: &DnsQuestion) -> Result<DnsPacket, Box<dyn Error>> {
    // Query the root nameserver
    let mut ns = root::get_root_nameserver();
    loop {
        let response = query_nameserver(question, ns)?;
        // Check that the response had a nonzero status code, or return an error
        // TODO(dylan): handle errors here. The most likely is an NXDOMAIN, which we should return
        // to the user; it's an authoritative statement that the domain does not exist. We might
        // also get a SERVFAIL or similar, suggesting we should probably try another server
        if response.flags.rcode != DnsRCode::NoError {
            return Err(format!(
                "Nonzero response code {:?} querying {:?}",
                response.flags.rcode, ns
            )
            .into());
        };

        // If we got answers, we're done!
        if response.answers.len() > 0 {
            return Ok(response);
        }

        // Otherwise we need to look at the next authority to query
        // TODO(dylan): hacks, assume we always get a glue record in addl records and start
        // by just looping through those until we find an A record
        if response.addl_recs.len() > 0 {
            for rr in response.addl_recs {
                // Hacks just assume it's an A record too. Proof of concept code!
                if rr.rr_type == DnsRRType::A {
                    ns = IpAddr::V4(rr.get_a_ip());
                    break;
                }
            }
            continue;
        } else {
            return Err(
                "No glue records. A normal server would help you. Ours won't right now.".into(),
            );
        }
    }
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
