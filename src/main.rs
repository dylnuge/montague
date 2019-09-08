use std::error;
use std::net;

mod dns;

use dns::protocol;
use dns::recursive;

// Make Result<T> an alias for a result with a boxed error in it. This lets
// us write methods that return multiple different types of errors more easily,
// but has the drawback that we can't statically determine what is in the box.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

// Main server thread entry point. Listens for a connection on
// localhost (127.0.0.1) UDP port 5300 and reads up to 500 bytes
fn listen_once() -> Result<()> {
    // First, open the UDP socket
    println!("Listening for UDP connection");
    let socket = net::UdpSocket::bind("127.0.0.1:5300")?;

    // Receive data from the user.
    // TODO(dylan): Up MTU, consider using an alloc here
    let mut buf = [0; 500];
    let (amt, src) = socket.recv_from(&mut buf)?;
    println!("Data received: {} bytes", amt);

    // Process the DNS packet received and print out some data from it
    let packet = match protocol::DnsPacket::from_bytes(&buf[..amt]) {
        Ok(x) => Ok(x),
        Err(e) => {
            println!("Invalid format!");
            match e.get_error_response() {
                Some(response) => {
                    let response_bytes = &response.to_bytes();
                    println!("Returning response {:?}", response);
                    socket.send_to(&response_bytes, &src)?;
                }
                None => {
                    println!("Not enough info to build a response, dropping connection");
                }
            }
            Err(e)
        }
    }?;
    println!("DNS Packet Received: {:?}", packet);

    // Confirm that the DNS packet contains exactly 1 question, or return an error
    // NOTE: The exact semantics of what to do with multiple questions as part of the same query is
    // unclear. Technically, they're allowed by RFC 1035, but there's practical issues (e.g. if two
    // different domains are queried for, what does an NXDOMAIN status code in the header
    // indicate?). Real nameservers seem to generally just discard (ignore) the additional
    // questions; rejecting them is a bit meaner.
    if packet.questions.len() != 1 {
        println!(
            "Question count was {}, we require it be 1",
            packet.questions.len()
        );
        return Err("Dropping out, implement a better thing here".into());
    };

    // Run a recursive query on our one question
    let mut results = recursive::resolve_question(&packet.questions[0])?;
    // Use the originating txid
    results.id = packet.id;
    // Set the RA bit TODO this should probably be owned by the resolver code
    results.flags.ra_bit = true;

    // Send the results back to the client
    println!("Returning results: {:?}", results);
    let response_bytes = &results.to_bytes();
    socket.send_to(&response_bytes, &src)?;

    Ok(())
}

fn main() -> Result<()> {
    listen_once()
}
