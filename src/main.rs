use std::net;
use std::error;
use std::str;

// Make Result<T> an alias for a result with a boxed error in it. This lets
// us write methods that return multiple different types of errors more easily,
// but has the drawback that we can't statically determine what is in the box.
type Result<T> = std::result::Result<T, Box<error::Error>>;

// Main server thread entry point. Listens for a connection on
// localhost (127.0.0.1) UDP port 5300 and reads up to 50 bytes
fn listen_once()  -> Result<()> {
    // First, open the UDP socket
    println!("Listening for UDP connection");
    let socket = net::UdpSocket::bind("127.0.0.1:5300")?;

    // Receive data from the user. For now, let's read in an arbitrary UTF-8
    // string and send it back out, like a networking "hello world"
    let mut buf = [0; 50];
    let (amt, source) = socket.recv_from(&mut buf)?;
    let username = str::from_utf8(&buf).expect("Data sent was not valid UTF-8");

    println!("Data received: {} bytes", amt);
    socket.send_to(format!("Hello {}", username).as_bytes(), &source)?;
    Ok(())
}

fn main() -> Result<()> {
    listen_once()
}
