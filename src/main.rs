use std::error;
use std::net;

mod dns;

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
    let packet = match dns::DnsPacket::from_bytes(&buf) {
        Ok(x) => Ok(x),
        Err(e) => {
            println!("Invalid format!");
            let response = e
                .get_error_response()
                .expect("Panic, could not construct response");
            println!("Returning response {:?}", response);
            let response_bytes = &response.to_bytes();
            socket.send_to(&response_bytes, &src)?;
            Err(e)
        }
    }?;
    println!("DNS Packet Received: {:?}", packet);

    // Build an NXDOMAIN answer for the domain queried for
    // (right now, we don't know any domains and can't behave recursively)
    let response = dns::nx_answer_from_query(&packet);
    println!("Response ready: {:?}", response);
    let response_bytes = &response.to_bytes();
    socket.send_to(&response_bytes, &src)?;

    Ok(())
}

fn main() -> Result<()> {
    listen_once()
}
