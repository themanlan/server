mod blocklist;
mod dns;

use std::net::UdpSocket;
use std::time::Duration;

use blocklist::Blocklist;

const LISTEN_ADDR: &str = "0.0.0.0:5354";
const UPSTREAM: &str = "1.1.1.1:53";

fn main() -> std::io::Result<()> {
    let server = UdpSocket::bind(LISTEN_ADDR)?;
    let blocklist = Blocklist::load("blocklist.txt");

    println!("listening on {LISTEN_ADDR}, forwarding to {UPSTREAM}");
    let mut query =  [0u8; 4096];

    loop {
        //Wait for query from 'client' 
        let (len, client) = server.recv_from(&mut query)?;
        let packet = &query[..len];

        match dns::parse_question(packet) {
            Some((name,qtype, end)) => { 
                if blocklist.is_blocked(&name) {
                    println!("BLOCKED {name} (type {qtype}) from {client}");
                    let resp = dns::build_blocked_response(packet, end, qtype);
                    server.send_to(&resp, client)?;
                    continue;
                }
                println!("query: {name} (type {qtype}) from {client}");
            }
            None => { eprintln!("malformed query from {client}");
                continue;
            }
        }

        //Fresh socket per query
        let upstream = UdpSocket::bind("0.0.0.0:0")?;
        upstream.set_read_timeout(Some(Duration::from_secs(2)))?;
        upstream.send_to(&query[..len], UPSTREAM)?;

        let mut response =  [0u8; 4096];
        match upstream.recv_from(&mut response) {
            Ok((rlen, _)) => {
                server.send_to(&response[..rlen], client)?;
            }
            Err(e) => eprintln!("upsteam failed: {e}"),
        }
    }
}

