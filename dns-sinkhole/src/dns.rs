


/// Extracts domain name and query type from a DNS query packet
/// returns None if the packet is malformed
pub fn parse_question(packet: &[u8]) -> Option<(String,u16,usize)> {
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
    packet.get(pos +3)?; //make sure the QCLASS is present too
    Some((labels.join("."), qtype, pos+4))
}

pub fn build_blocked_response(query: &[u8], question_end: usize, qtype: u16) -> Vec<u8> {
    // Start from the query's header + question.
    let mut resp = query[..question_end].to_vec();

    resp[2] = 0x80 | (query[2] & 0x01); // QR=1 (this is a response), keep the client's RD bit
    resp[3] = 0x80;                     // RA=1 (recursion available), RCODE=0 (no error)

    let rdata_len: usize = match qtype {
        1 => 4,   // A: an IPv4 address is 4 bytes
        28 => 16, // AAAA: an IPv6 address is 16 bytes
        _ => 0,   // other types: reply "no error, no answers"
    };
    let ancount: u16 = if rdata_len > 0 { 1 } else { 0 };
    resp[6..8].copy_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    resp[8..12].fill(0); // NSCOUNT and ARCOUNT = 0 (this also drops EDNS)

    if rdata_len > 0 {
        resp.extend_from_slice(&[0xC0, 0x0C]);                 // name: pointer to offset 12 (the question's name)
        resp.extend_from_slice(&qtype.to_be_bytes());          // TYPE
        resp.extend_from_slice(&1u16.to_be_bytes());           // CLASS = IN
        resp.extend_from_slice(&60u32.to_be_bytes());          // TTL: 60 seconds
        resp.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        resp.extend(std::iter::repeat(0u8).take(rdata_len));   // 0.0.0.0 or ::
    }
    resp
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
