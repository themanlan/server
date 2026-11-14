use std::net::UdpSocket;
use std::time::Duration;

const LISTEN_ADDR: &str = "0.0.0.0:5354";
const UPSTREAM: &str = "1.1.1.1:53";

/// Extracts domain name and query type from a DNS query packet
/// returns None if the packet is malformed
fn parse_question(packet: &[u8]) -> Option<(String,u16)> {
    //Header is 12 bytes; QDCOUNT lives at bytes 4..6.
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4],packet[5]]);
    if qdcount != 1 {
        return None;
    }
    
    let mut pos = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        // .get() returns None
        let len = *packet.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break; //zero byte terminates the name
        }
        if len & 0xC0 != 0 {
            return None; //compression pointer
        }
        let label = packet.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).to_lowercase());
        pos += len;
    }
    
    // The two bytes of QTYPE follow the name
    let qtype = u16::from_be_bytes([*packet.get(pos)?, *packet.get(pos + 1)?]);
    Some((labels.join("."), qtype))
}



fn main() -> std::io::Result<()> {
    let server = UdpSocket::bind(LISTEN_ADDR)?;
    println!("listening on {LISTEN_ADDR}, forwarding to {UPSTREAM}");
    let mut query =  [0u8; 4096];

    loop {
        //Wait for query from 'client' 
        let (len, client) = server.recv_from(&mut query)?;
        

        match parse_question(&query[..len ]) {
            Some((name,qtype)) => println!("query: {name} (type {qtype}) from {client}"),
            None => eprintln!("malformed query from {client}"),
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_com() {
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(b"\x07example\x03com\x00");
        p.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        assert_eq!(parse_question(&p), Some(("example.com".to_string(), 1)));
    }

    #[test]
    fn rejects_truncated_packet() {
        assert_eq!(parse_question(&[0u8; 5]), None);
    }
}
