// Recursive resolver functionality

mod root;

use std::error::Error;
use std::net::{IpAddr, UdpSocket};

use super::protocol::{
    DnsClass, DnsFlags, DnsOpcode, DnsPacket, DnsQuestion, DnsRCode, DnsRRType, DnsRecordData,
    DnsResourceRecord,
};

// Right now this doesn't use caching, doesn't try another nameserver if one fails, and a lot of
// other little things I'd like to add to it.
pub fn resolve_question(question: &DnsQuestion) -> Result<DnsPacket, Box<dyn Error>> {
    // Query the root nameserver
    let mut ns = root::get_root_nameserver();
    loop {
        println!("Asking authority at {:?} question: {:?}", ns, question);
        let response = query_nameserver(question, ns)?;
        println!("Got response from authority: {:?}", response);
        // Check that the response had a nonzero status code, or return an error
        if response.flags.rcode != DnsRCode::NoError {
            if response.flags.rcode == DnsRCode::NXDomain {
                return Ok(response);
            }

            // TODO(dylan): Handle more errors. We might also get a SERVFAIL or similar, suggesting we
            // should probably try another server
            return Err(format!(
                "Nonzero response code {:?} querying {:?}",
                response.flags.rcode, ns
            )
            .into());
        };

        // If we got answers, we move on to answer handling!
        if response.answers.len() > 0 {
            return handle_answers(response);
        }

        // Without an answer, we need to look at the next authority to query. Per RFC 1034, it's
        // legal for the nameservers section to include the SOA for the nameserver we're talking
        // to, as well as NS records for nameservers to talk to next. We'll just take the first NS
        // record returned (this is a common pattern; NS records are often sent in random orders
        // for this reason).
        let mut ns_answer = None;
        for rr in &response.nameservers {
            if rr.rr_type == DnsRRType::NS {
                ns_answer = Some(rr);
                break;
            }
        }
        if ns_answer == None {
            // In theory this is disallowed by spec
            return Err(format!("No error, answer, or nameservers from response").into());
        }

        // We may have a glue record for this nameserver; use it if we find it
        let glue_record_ip = find_glue_record_for_ns(ns_answer.unwrap(), &response.addl_recs);
        match glue_record_ip {
            None => {
                ns = get_nameserver_address(ns_answer.unwrap())?;
            }
            Some(ip) => {
                ns = ip;
            }
        }
    }
}

fn handle_answers(mut response: DnsPacket) -> Result<DnsPacket, Box<dyn Error>> {
    // If our answers have a CNAME, we have to (recursively) go lookup the CNAME too. If it has
    // multiple CNAMEs, or a CNAME and other records, it's breaking the spec; we'll just ignore
    // that case right now, though we might want to return a FORMERR or something?
    if response.answers.len() == 1 {
        match &response.answers[0].record {
            DnsRecordData::CNAME(labels) => {
                // We're asking a question for the canonical name, now. Class and type stay the
                // same.
                let question = DnsQuestion {
                    qname: labels.to_owned(),
                    // It should be safe to assume there's one and only one question here, though
                    // we may want to assert it, since a bad server could strip questions or
                    // something else weird.
                    qclass: response.questions[0].qclass,
                    qtype: response.questions[0].qtype,
                };
                // Note that resolve_question calls this function, so if our reply has another
                // CNAME in it, that will be handled before it's returned back to us
                let reply = resolve_question(&question)?;

                // We add the answers, nameservers, and additional records from the CNAME reply to
                // our original answer, but we don't change the question
                response.answers.extend(reply.answers);
                response.nameservers.extend(reply.nameservers);
                response.addl_recs.extend(reply.addl_recs);
            }
            _ => (),
        }
    }
    Ok(response)
}

fn find_glue_record_for_ns(
    ns: &DnsResourceRecord,
    records: &Vec<DnsResourceRecord>,
) -> Option<IpAddr> {
    let ns_name = match &ns.record {
        DnsRecordData::NS(name) => name,
        _ => panic!("NS record data is not stored properly"),
    };

    for rr in records {
        if &rr.name == ns_name {
            match rr.record {
                DnsRecordData::A(ip_addr) => return Some(IpAddr::V4(ip_addr)),
                _ => (),
            }
        }
    }
    return None;
}

fn get_nameserver_address(ns: &DnsResourceRecord) -> Result<IpAddr, Box<dyn Error>> {
    // TODO(dylan): We should detect an infinite loop being caused by a missing glue record. This
    // can happen if we're asked to talk to, for instance, "ns.example.com" to find out where
    // "example.com" is. We'll keep repeating the same NS lookup over and over.
    let ns_name = match &ns.record {
        DnsRecordData::NS(name) => name,
        _ => panic!("NS record data is not stored properly"),
    };
    let question = DnsQuestion {
        // Again, label copying seems inefficient
        qname: ns_name.to_owned(),
        // Again, hardcoding IPv4
        qtype: DnsRRType::A,
        qclass: DnsClass::IN,
    };
    // XXX this is definitely not a production server without loop detection
    let result = resolve_question(&question)?;
    for answer in &result.answers {
        if answer.rr_type == DnsRRType::A {
            match answer.record {
                DnsRecordData::A(addr) => return Ok(IpAddr::V4(addr)),
                _ => continue,
            }
        }
    }
    return Err(format!(
        "Got result without A records when doing nameserver lookup: {:?}",
        result
    )
    .into());
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
        // TODO not a great practice that this test requires a network connection
        let ns = IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10));
        let packet = query_nameserver(&question, ns).expect("query should have worked");
        println!("{:?}", packet);
    }
}
