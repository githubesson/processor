use std::io::{BufRead, BufReader, Read};

use crate::record::{OwnedRecord, Record};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid line format at line {0}")]
    InvalidFormat(usize),
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn trim_newline(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    &line[..end]
}

fn find_credential_separator(line: &[u8], after_protocol_start: usize) -> Option<usize> {
    let after_protocol = &line[after_protocol_start..];

    let slash_pos = after_protocol.iter().position(|&b| b == b'/');
    let at_pos = after_protocol.iter().position(|&b| b == b'@');

    match (slash_pos, at_pos) {
        (Some(slash), Some(at)) if at < slash => {
            find_colon_after_path(after_protocol, slash)
                .map(|pos| after_protocol_start + pos)
        }
        (Some(slash), _) => {
            find_colon_after_path(after_protocol, slash)
                .map(|pos| after_protocol_start + pos)
        }
        (None, Some(at)) => {
            after_protocol[at + 1..]
                .iter()
                .position(|&b| b == b':')
                .map(|pos| after_protocol_start + at + 1 + pos)
        }
        (None, None) => {
            let colons: Vec<usize> = after_protocol
                .iter()
                .enumerate()
                .filter(|(_, &b)| b == b':')
                .map(|(i, _)| i)
                .collect();

            match colons.len() {
                0 | 1 => None,
                2 => Some(after_protocol_start + colons[0]),
                _ => {
                    let potential_port = &after_protocol[colons[0] + 1..colons[1]];
                    if potential_port.iter().all(|&b| b.is_ascii_digit()) && potential_port.len() <= 5 {
                        Some(after_protocol_start + colons[1])
                    } else {
                        Some(after_protocol_start + colons[0])
                    }
                }
            }
        }
    }
}

fn find_colon_after_path(data: &[u8], slash_pos: usize) -> Option<usize> {
    data[slash_pos..]
        .iter()
        .position(|&b| b == b':')
        .map(|pos| slash_pos + pos)
}

pub fn parse_line(line: &[u8]) -> Option<Record<'_>> {
    let protocol_pos = find_subsequence(line, b"://")?;
    let url_end = find_credential_separator(line, protocol_pos + 3)?;
    let url = &line[..url_end];

    let creds = &line[url_end + 1..];
    let first_colon = creds.iter().position(|&b| b == b':')?;
    let username = &creds[..first_colon];
    let password = &creds[first_colon + 1..];

    Some(Record {
        line_num: 0,
        url,
        username,
        password,
    })
}

pub struct Parser<R> {
    reader: BufReader<R>,
    line_buf: Vec<u8>,
    line_count: usize,
    skip_invalid: bool,
}

impl<R: Read> Parser<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            line_buf: Vec::with_capacity(4096),
            line_count: 0,
            skip_invalid: true,
        }
    }
}

impl<R: Read> Iterator for Parser<R> {
    type Item = Result<OwnedRecord, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.line_buf.clear();
            match self.reader.read_until(b'\n', &mut self.line_buf) {
                Ok(0) => return None,
                Ok(_) => {
                    self.line_count += 1;
                    let line = trim_newline(&self.line_buf);

                    if line.is_empty() {
                        if self.skip_invalid {
                            continue;
                        } else {
                            return Some(Err(ParseError::InvalidFormat(self.line_count)));
                        }
                    }

                    match parse_line(line) {
                        Some(record) => return Some(Ok(record.to_owned())),
                        None => {
                            if self.skip_invalid {
                                continue;
                            } else {
                                return Some(Err(ParseError::InvalidFormat(self.line_count)));
                            }
                        }
                    }
                }
                Err(e) => return Some(Err(ParseError::Io(e))),
            }
        }
    }
}

pub fn parse_mmap(data: &[u8]) -> impl Iterator<Item = Record<'_>> {
    data.split(|&b| b == b'\n')
        .map(trim_newline)
        .filter(|line| !line.is_empty())
        .filter_map(parse_line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_line() {
        let line = b"https://example.com/login:user123:password456";
        let record = parse_line(line).expect("Should parse");

        assert_eq!(record.url, b"https://example.com/login");
        assert_eq!(record.username, b"user123");
        assert_eq!(record.password, b"password456");
    }

    #[test]
    fn test_parse_with_port() {
        let line = b"https://example.com:8080/path:admin:secret";
        let record = parse_line(line).expect("Should parse");

        assert_eq!(record.url, b"https://example.com:8080/path");
        assert_eq!(record.username, b"admin");
        assert_eq!(record.password, b"secret");
    }

    #[test]
    fn test_parse_no_path() {
        let line = b"https://example.com:user:pass";
        let record = parse_line(line).expect("Should parse");

        assert_eq!(record.url, b"https://example.com");
        assert_eq!(record.username, b"user");
        assert_eq!(record.password, b"pass");
    }

    #[test]
    fn test_parse_with_port_no_path() {
        let line = b"https://example.com:443:user:pass";
        let record = parse_line(line).expect("Should parse");

        assert_eq!(record.url, b"https://example.com:443");
        assert_eq!(record.username, b"user");
        assert_eq!(record.password, b"pass");
    }

    #[test]
    fn test_parse_colon_in_password() {
        let line = b"https://site.com/login:user:pass:word:123";
        let record = parse_line(line).expect("Should parse");

        assert_eq!(record.url, b"https://site.com/login");
        assert_eq!(record.username, b"user");
        assert_eq!(record.password, b"pass:word:123");
    }

    #[test]
    fn test_parse_empty_password() {
        let line = b"https://site.com:user:";
        let record = parse_line(line).expect("Should parse");

        assert_eq!(record.username, b"user");
        assert_eq!(record.password, b"");
    }

    #[test]
    fn test_parse_not_saved_password() {
        let line = b"https://site.com:user:[NOT_SAVED]";
        let record = parse_line(line).expect("Should parse");

        assert_eq!(record.password, b"[NOT_SAVED]");
    }

    #[test]
    fn test_parse_android_scheme() {
        let line = b"android://hash123@com.example.app/:user:pass";
        let record = parse_line(line).expect("Should parse");

        assert_eq!(record.url, b"android://hash123@com.example.app/");
        assert_eq!(record.username, b"user");
        assert_eq!(record.password, b"pass");
    }

    #[test]
    fn test_parse_email_username() {
        let line = b"https://login.live.com/oauth:user@example.com:MyP@ss!";
        let record = parse_line(line).expect("Should parse");

        assert_eq!(record.url, b"https://login.live.com/oauth");
        assert_eq!(record.username, b"user@example.com");
        assert_eq!(record.password, b"MyP@ss!");
    }

    #[test]
    fn test_parse_special_chars_password() {
        let line = b"https://example.com/:user:g2ZkyBW6f<*4ejc";
        let record = parse_line(line).expect("Should parse");

        assert_eq!(record.username, b"user");
        assert_eq!(record.password, b"g2ZkyBW6f<*4ejc");
    }

    #[test]
    fn test_streaming_parser() {
        let data = "https://a.com:u1:p1\nhttps://b.com:u2:p2\n";
        let parser = Parser::new(data.as_bytes());
        let records: Vec<_> = parser.filter_map(Result::ok).collect();

        assert_eq!(records.len(), 2);
        assert_eq!(&*records[0].url, b"https://a.com");
        assert_eq!(&*records[1].url, b"https://b.com");
    }

    #[test]
    fn test_parser_skips_invalid() {
        let data = "https://a.com:u:p\ninvalid line\nhttps://b.com:u:p\n";
        let parser = Parser::new(data.as_bytes());
        let records: Vec<_> = parser.filter_map(Result::ok).collect();

        assert_eq!(records.len(), 2);
    }
}
