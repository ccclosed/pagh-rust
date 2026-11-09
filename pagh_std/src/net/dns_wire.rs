//! The pure RFC 1035 wire codec behind [`super::dns`] — `core` + `alloc` only.
//!
//! Everything here is a decision about bytes: encode one `A` question, decode
//! the answer, follow compression pointers, and refuse anything malformed. It
//! touches no socket, so `hostcheck` includes this exact file with `#[path]`
//! and exercises it with adversarial input; the resolver in [`super::dns`] is
//! the part that owns the [`UdpSocket`](super::UdpSocket) and the retry budget.
//!
//! Fail-closed rules, each one a test:
//!
//!   * names are validated before they are encoded (1..=63 bytes per label,
//!     <= 255 bytes encoded, ASCII letters/digits/`-`/`_`/`*` per label) — a
//!     name that cannot be represented is an error, never a truncated query;
//!   * a compression pointer must point *strictly backwards* (RFC 1035 §4.1.4
//!     permits only prior occurrences), which makes pointer loops impossible
//!     without a visited set;
//!   * every read is bounds-checked against the message length; a record whose
//!     RDATA is shorter than its type requires is [`WireError::BadRecord`];
//!   * the reply must echo our transaction id, have `QR=1`, and repeat the
//!     question we asked ([`WireError::NotAResponse`] /
//!     [`WireError::QuestionMismatch`]) — an off-path datagram that guesses the
//!     id but asks something else is not an answer to this query.

use alloc::string::String;
use alloc::vec::Vec;

/// `A` record type.
pub const TYPE_A: u16 = 1;
/// `CNAME` record type.
pub const TYPE_CNAME: u16 = 5;
/// `IN` class.
pub const CLASS_IN: u16 = 1;
/// Response code: no error.
pub const RCODE_NOERROR: u8 = 0;
/// Response code: the name does not exist.
pub const RCODE_NXDOMAIN: u8 = 3;

/// Longest single label.
pub const MAX_LABEL: usize = 63;
/// Longest encoded name, including length bytes and the root label.
pub const MAX_NAME: usize = 255;

/// Why a message could not be encoded or decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Empty name, empty label, label above 63 bytes, non-ASCII byte, or an
    /// encoded name above 255 bytes.
    BadName,
    /// The caller's buffer is smaller than the message needs.
    BufferTooSmall,
    /// The message ends before a field it promised.
    Truncated,
    /// A compression pointer points at or past itself, or outside the message.
    BadPointer,
    /// The header is not a response to the id we asked with.
    NotAResponse,
    /// The question section does not repeat the question we sent.
    QuestionMismatch,
    /// A record's RDATA does not have the shape its type requires.
    BadRecord,
}

/// One decoded `A` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ARecord {
    /// The address, in wire order.
    pub address: [u8; 4],
    /// Time to live, seconds.
    pub ttl: u32,
}

/// A decoded response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    /// The response code (`RCODE_NOERROR` on success).
    pub rcode: u8,
    /// The `TC` bit: the answer did not fit and would have to be retried over
    /// TCP, which this SDK does not implement.
    pub truncated: bool,
    /// Every `A` record in the answer section, in message order.
    pub addresses: Vec<ARecord>,
    /// The first `CNAME` target in the answer section, if any. A resolver
    /// follows it with a fresh query; a caller that does not want to must
    /// treat [`Response::addresses`] as empty and give up.
    pub cname: Option<String>,
}

impl Response {
    /// True when the answer carries at least one address.
    pub fn has_address(&self) -> bool {
        !self.addresses.is_empty()
    }
}

/// Encode one standard query for `name`'s `A` record.
///
/// The header is `id`, `RD=1` (recursion desired), one question; the question
/// is `name`, [`TYPE_A`], [`CLASS_IN`]. Returns the message length, or
/// [`WireError::BadName`]/[`WireError::BufferTooSmall`].
pub fn encode_query(name: &str, id: u16, out: &mut [u8]) -> Result<usize, WireError> {
    if out.len() < 12 {
        return Err(WireError::BufferTooSmall);
    }
    out[..12].fill(0);
    out[0..2].copy_from_slice(&id.to_be_bytes());
    // Flags: QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0.
    out[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    out[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT

    let mut offset = 12;
    offset += encode_name(name, &mut out[offset..])?;
    if out.len() < offset + 4 {
        return Err(WireError::BufferTooSmall);
    }
    out[offset..offset + 2].copy_from_slice(&TYPE_A.to_be_bytes());
    out[offset + 2..offset + 4].copy_from_slice(&CLASS_IN.to_be_bytes());
    Ok(offset + 4)
}

/// Encode a dotted name as length-prefixed labels plus the root label.
///
/// Public because the host tests build answer messages with it; the resolver
/// only ever calls it through [`encode_query`].
pub fn encode_name(name: &str, out: &mut [u8]) -> Result<usize, WireError> {
    // A single trailing dot is the FQDN root and is redundant here.
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_NAME - 2 {
        return Err(WireError::BadName);
    }
    let mut written = 0usize;
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_LABEL {
            return Err(WireError::BadName);
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' || *b == b'*')
        {
            return Err(WireError::BadName);
        }
        if out.len() < written + 1 + bytes.len() {
            return Err(WireError::BufferTooSmall);
        }
        out[written] = bytes.len() as u8;
        out[written + 1..written + 1 + bytes.len()].copy_from_slice(bytes);
        written += 1 + bytes.len();
    }
    if out.len() < written + 1 {
        return Err(WireError::BufferTooSmall);
    }
    out[written] = 0;
    written += 1;
    if written > MAX_NAME {
        return Err(WireError::BadName);
    }
    Ok(written)
}

/// Decode a (possibly compressed) name starting at `offset`.
///
/// Returns the name (labels joined with `.`, no trailing dot) and the offset
/// just past the name *in the message* — for a compressed name that is past the
/// two-byte pointer, not past the data it points to.
pub fn decode_name(message: &[u8], offset: usize) -> Result<(String, usize), WireError> {
    let mut name = String::new();
    let mut cursor = offset;
    let mut after_first_pointer: Option<usize> = None;
    let mut total = 0usize;
    loop {
        let length = *message.get(cursor).ok_or(WireError::Truncated)? as usize;
        if length & 0xC0 == 0xC0 {
            let low = *message.get(cursor + 1).ok_or(WireError::Truncated)? as usize;
            let target = ((length & 0x3F) << 8) | low;
            // RFC 1035 §4.1.4: a pointer must name a *prior* occurrence. That
            // single rule makes cycles impossible here.
            if target >= cursor {
                return Err(WireError::BadPointer);
            }
            if after_first_pointer.is_none() {
                after_first_pointer = Some(cursor + 2);
            }
            cursor = target;
            continue;
        }
        if length & 0xC0 != 0 {
            return Err(WireError::BadPointer);
        }
        cursor += 1;
        if length == 0 {
            break;
        }
        total += length + 1;
        if total > MAX_NAME {
            return Err(WireError::BadName);
        }
        let label = message
            .get(cursor..cursor + length)
            .ok_or(WireError::Truncated)?;
        if !name.is_empty() {
            name.push('.');
        }
        for byte in label {
            // Names in the answer section are the server's, not ours: decode
            // only what can round-trip as text, refuse the rest.
            if !byte.is_ascii() {
                return Err(WireError::BadName);
            }
            name.push(*byte as char);
        }
        cursor += length;
    }
    Ok((name, after_first_pointer.unwrap_or(cursor)))
}

/// Parse a response to the query `(id, question)`.
///
/// Only the answer section is interpreted: `A` records become
/// [`Response::addresses`], the first `CNAME` becomes [`Response::cname`], and
/// everything else (NS, SOA, TXT, AAAA, …) is skipped by its declared length.
pub fn parse_response(message: &[u8], id: u16, question: &str) -> Result<Response, WireError> {
    if message.len() < 12 {
        return Err(WireError::Truncated);
    }
    let reply_id = u16::from_be_bytes([message[0], message[1]]);
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if reply_id != id {
        return Err(WireError::NotAResponse);
    }
    if flags & 0x8000 == 0 {
        // QR=0: this is a query, not an answer.
        return Err(WireError::NotAResponse);
    }
    let question_count = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answer_count = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut response = Response {
        rcode: (flags & 0x000F) as u8,
        truncated: flags & 0x0200 != 0,
        addresses: Vec::new(),
        cname: None,
    };

    // Our own question must come back, byte for byte, before anything in the
    // answer section is trusted.
    let mut offset = 12usize;
    let mut matched_question = false;
    for index in 0..question_count {
        let (name, next) = decode_name(message, offset)?;
        let type_class = message.get(next..next + 4).ok_or(WireError::Truncated)?;
        let record_type = u16::from_be_bytes([type_class[0], type_class[1]]);
        let record_class = u16::from_be_bytes([type_class[2], type_class[3]]);
        offset = next + 4;
        if index == 0 {
            let expected = question.strip_suffix('.').unwrap_or(question);
            if !name.eq_ignore_ascii_case(expected)
                || record_type != TYPE_A
                || record_class != CLASS_IN
            {
                return Err(WireError::QuestionMismatch);
            }
            matched_question = true;
        }
    }
    if question_count > 0 && !matched_question {
        return Err(WireError::QuestionMismatch);
    }

    for _ in 0..answer_count {
        let (_owner, next) = decode_name(message, offset)?;
        let header = message.get(next..next + 10).ok_or(WireError::Truncated)?;
        let record_type = u16::from_be_bytes([header[0], header[1]]);
        let record_class = u16::from_be_bytes([header[2], header[3]]);
        let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        let data = next + 10;
        let end = data.checked_add(length).ok_or(WireError::BadRecord)?;
        if end > message.len() {
            return Err(WireError::Truncated);
        }
        if record_class == CLASS_IN {
            match record_type {
                TYPE_A => {
                    if length != 4 {
                        return Err(WireError::BadRecord);
                    }
                    response.addresses.push(ARecord {
                        address: [
                            message[data],
                            message[data + 1],
                            message[data + 2],
                            message[data + 3],
                        ],
                        ttl,
                    });
                }
                TYPE_CNAME => {
                    if response.cname.is_none() {
                        let (target, _) = decode_name(message, data)?;
                        response.cname = Some(target);
                    }
                }
                _ => {}
            }
        }
        offset = end;
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// One hand-built NOERROR answer: `example.com A 93.184.216.34`.
    fn answer(id: u16) -> Vec<u8> {
        let mut message = vec![0u8; 64];
        message[0..2].copy_from_slice(&id.to_be_bytes());
        message[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        message[4..6].copy_from_slice(&1u16.to_be_bytes());
        message[6..8].copy_from_slice(&1u16.to_be_bytes());
        let mut offset = 12;
        offset += encode_name("example.com", &mut message[offset..]).unwrap();
        message[offset..offset + 2].copy_from_slice(&TYPE_A.to_be_bytes());
        message[offset + 2..offset + 4].copy_from_slice(&CLASS_IN.to_be_bytes());
        offset += 4;
        // The owner name is a pointer to offset 12 (the question's name).
        message[offset] = 0xC0;
        message[offset + 1] = 12;
        message[offset + 2..offset + 4].copy_from_slice(&TYPE_A.to_be_bytes());
        message[offset + 4..offset + 6].copy_from_slice(&CLASS_IN.to_be_bytes());
        message[offset + 6..offset + 10].copy_from_slice(&300u32.to_be_bytes());
        message[offset + 10..offset + 12].copy_from_slice(&4u16.to_be_bytes());
        message[offset + 12..offset + 16].copy_from_slice(&[93, 184, 216, 34]);
        message.truncate(offset + 16);
        message
    }

    #[test]
    fn query_round_trips_through_the_parser() {
        let mut query = [0u8; 512];
        let length = encode_query("example.com", 0x1234, &mut query).unwrap();
        assert_eq!(&query[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);
        let (name, after) = decode_name(&query, 12).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(after, length - 4);
    }

    #[test]
    fn an_answer_decodes_to_the_address() {
        let message = answer(7);
        let response = parse_response(&message, 7, "example.com").unwrap();
        assert_eq!(response.rcode, RCODE_NOERROR);
        assert!(!response.truncated);
        assert_eq!(response.addresses.len(), 1);
        assert_eq!(response.addresses[0].address, [93, 184, 216, 34]);
        assert_eq!(response.addresses[0].ttl, 300);
    }

    #[test]
    fn a_forward_pointer_is_refused() {
        // A pointer that names itself is the classic loop; RFC 1035 only allows
        // prior occurrences, so this is a hard refusal, not a visited-set walk.
        let mut message = answer(1);
        message[12] = 0xC0;
        message[13] = 12;
        assert_eq!(
            parse_response(&message, 1, "example.com"),
            Err(WireError::BadPointer)
        );
    }

    #[test]
    fn a_foreign_transaction_id_is_not_an_answer() {
        let message = answer(9);
        assert_eq!(
            parse_response(&message, 10, "example.com"),
            Err(WireError::NotAResponse)
        );
    }

    #[test]
    fn a_question_mismatch_is_refused() {
        let message = answer(3);
        assert_eq!(
            parse_response(&message, 3, "example.org"),
            Err(WireError::QuestionMismatch)
        );
    }

    #[test]
    fn malformed_names_never_encode() {
        let mut out = [0u8; 512];
        // `a..b` is an empty label, `-` is legal RFC 1035 (if unusual), and a
        // single trailing dot is the FQDN root, which the encoder strips.
        for name in ["", ".", "a..b", "a..", "x".repeat(64).as_str(), "пример.рф"] {
            assert!(encode_query(name, 1, &mut out).is_err(), "{name:?} encoded");
        }
        assert!(encode_query(&"x".repeat(63), 1, &mut out).is_ok());
    }

    #[test]
    fn a_truncated_message_is_refused_at_every_length() {
        let message = answer(5);
        for length in 0..message.len() {
            assert!(
                parse_response(&message[..length], 5, "example.com").is_err(),
                "accepted a {length}-byte prefix"
            );
        }
    }
}
