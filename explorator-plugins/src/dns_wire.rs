//! Minimal RFC 1035 DNS message encoding/decoding — just enough to send a
//! single-question query and read back A/AAAA/CNAME/MX/TXT/NS answers.
//! Hand-rolled instead of pulling in a resolver crate, since the wire
//! format for this subset is small and stable.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Build a standard recursive query for `name` (a hostname, no trailing
/// dot required) asking for records of type `qtype`.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(name.len() + 16);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0u16.to_be_bytes()); // arcount

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0); // root label

    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());
    buf
}

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Mx { preference: u16, exchange: String },
    Txt(String),
    Other,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub rtype: u16,
    pub rdata: RData,
}

/// Parse a response datagram, verifying it answers `expected_id`. Returns
/// `Some(vec![])` for a well-formed response with rcode != 0 (e.g.
/// NXDOMAIN) and `None` if the datagram is too malformed to trust at all.
pub fn parse_response(buf: &[u8], expected_id: u16) -> Option<Vec<Record>> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x000F != 0 {
        return Some(Vec::new());
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        let (_name, next) = read_name(buf, pos)?;
        if next + 4 > buf.len() {
            return None;
        }
        pos = next + 4; // qtype + qclass
    }

    let mut records = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (_name, next) = read_name(buf, pos)?;
        pos = next;
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > buf.len() {
            break;
        }
        let rdata_start = pos;

        let rdata = match rtype {
            TYPE_A if rdlength == 4 => {
                RData::A(Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]))
            }
            TYPE_AAAA if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[pos..pos + 16]);
                RData::Aaaa(Ipv6Addr::from(octets))
            }
            TYPE_CNAME => match read_name(buf, rdata_start) {
                Some((n, _)) => RData::Cname(n),
                None => RData::Other,
            },
            TYPE_NS => match read_name(buf, rdata_start) {
                Some((n, _)) => RData::Ns(n),
                None => RData::Other,
            },
            TYPE_MX if rdlength >= 2 => {
                let preference = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
                match read_name(buf, pos + 2) {
                    Some((exchange, _)) => RData::Mx { preference, exchange },
                    None => RData::Other,
                }
            }
            TYPE_TXT => {
                let mut s = String::new();
                let mut p = rdata_start;
                let end = rdata_start + rdlength;
                while p < end {
                    let len = buf[p] as usize;
                    p += 1;
                    if p + len > end {
                        break;
                    }
                    s.push_str(&String::from_utf8_lossy(&buf[p..p + len]));
                    p += len;
                }
                RData::Txt(s)
            }
            _ => RData::Other,
        };

        records.push(Record { rtype, rdata });
        pos = rdata_start + rdlength;
    }

    Some(records)
}

/// Reads a (possibly compressed) DNS name starting at `pos`. Returns the
/// decoded dotted name and the offset immediately after it in the
/// original stream (i.e. after any compression pointer, not after the
/// jumped-to location).
fn read_name(buf: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = pos;
    let mut end_pos = None;
    let mut jumps = 0;

    loop {
        if cursor >= buf.len() {
            return None;
        }
        let len = buf[cursor];
        if len == 0 {
            if end_pos.is_none() {
                end_pos = Some(cursor + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if cursor + 1 >= buf.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (buf[cursor + 1] as usize);
            if end_pos.is_none() {
                end_pos = Some(cursor + 2);
            }
            jumps += 1;
            if jumps > 20 {
                return None; // guard against pointer loops
            }
            cursor = ptr;
            continue;
        }
        let label_len = len as usize;
        cursor += 1;
        if cursor + label_len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[cursor..cursor + label_len]).to_string());
        cursor += label_len;
    }

    Some((labels.join("."), end_pos.unwrap_or(cursor)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_query_with_correct_header_and_question() {
        let packet = build_query(0x1234, "example.com", TYPE_A);
        assert_eq!(&packet[0..2], &[0x12, 0x34]); // id
        assert_eq!(&packet[2..4], &[0x01, 0x00]); // flags: RD
        assert_eq!(&packet[4..6], &[0x00, 0x01]); // qdcount = 1

        // question: 7"example"3"com"0
        let q = &packet[12..];
        assert_eq!(q[0], 7);
        assert_eq!(&q[1..8], b"example");
        assert_eq!(q[8], 3);
        assert_eq!(&q[9..12], b"com");
        assert_eq!(q[12], 0);
        let qtype = u16::from_be_bytes([q[13], q[14]]);
        assert_eq!(qtype, TYPE_A);
    }

    /// Hand-assembled response for a single-question "A" query returning
    /// one A record, using a compression pointer for the answer's name.
    fn sample_a_response(id: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x8180u16.to_be_bytes()); // response, RD+RA, rcode 0
        buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        buf.extend_from_slice(&1u16.to_be_bytes()); // ancount
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        // question: example.com A IN
        buf.push(7);
        buf.extend_from_slice(b"example");
        buf.push(3);
        buf.extend_from_slice(b"com");
        buf.push(0);
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());

        // answer: name = pointer to offset 12, type A, class IN, ttl, rdlength=4, ip
        buf.extend_from_slice(&0xC00Cu16.to_be_bytes());
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&300u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[93, 184, 216, 34]);

        buf
    }

    #[test]
    fn parses_a_record_with_name_compression() {
        let id = 0xBEEF;
        let response = sample_a_response(id);
        let records = parse_response(&response, id).expect("should parse");
        assert_eq!(records.len(), 1);
        match &records[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("expected A record, got {other:?}"),
        }
    }

    #[test]
    fn rejects_mismatched_transaction_id() {
        let response = sample_a_response(0xBEEF);
        assert!(parse_response(&response, 0xDEAD).is_none());
    }

    #[test]
    fn nxdomain_yields_empty_records_not_none() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0x8183u16.to_be_bytes()); // rcode 3 = NXDOMAIN
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let records = parse_response(&buf, 1).expect("should still parse header");
        assert!(records.is_empty());
    }
}
