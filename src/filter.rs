use std::collections::HashSet;

use regex::bytes::Regex;

use crate::record::{OwnedRecord, Record};

pub struct Filter {
    url_patterns: Vec<Regex>,
    domain_whitelist: Option<HashSet<Vec<u8>>>,
    domain_blacklist: Option<HashSet<Vec<u8>>>,
}

impl Filter {
    pub fn new() -> Self {
        Self {
            url_patterns: Vec::new(),
            domain_whitelist: None,
            domain_blacklist: None,
        }
    }

    pub fn add_url_pattern(&mut self, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.url_patterns.push(regex);
        Ok(())
    }

    pub fn set_domain_whitelist(&mut self, domains: Vec<String>) {
        self.domain_whitelist = Some(
            domains
                .into_iter()
                .map(|d| d.to_lowercase().into_bytes())
                .collect(),
        );
    }

    pub fn set_domain_blacklist(&mut self, domains: Vec<String>) {
        self.domain_blacklist = Some(
            domains
                .into_iter()
                .map(|d| d.to_lowercase().into_bytes())
                .collect(),
        );
    }

    pub fn matches(&self, record: &Record) -> bool {
        let domain = extract_domain(record.url);

        if let Some(ref blacklist) = self.domain_blacklist {
            if let Some(ref d) = domain {
                let lower = d.to_ascii_lowercase();
                if blacklist.contains(&lower) {
                    return false;
                }
            }
        }

        if let Some(ref whitelist) = self.domain_whitelist {
            if let Some(ref d) = domain {
                let lower = d.to_ascii_lowercase();
                if !whitelist.contains(&lower) && !domain_matches_any(&lower, whitelist) {
                    return false;
                }
            } else {
                return false;
            }
        }

        if !self.url_patterns.is_empty() {
            let matches_any = self.url_patterns.iter().any(|p| p.is_match(record.url));
            if !matches_any {
                return false;
            }
        }

        true
    }

    pub fn matches_owned(&self, record: &OwnedRecord) -> bool {
        self.matches(&record.as_ref())
    }

    pub fn is_empty(&self) -> bool {
        self.url_patterns.is_empty()
            && self.domain_whitelist.is_none()
            && self.domain_blacklist.is_none()
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_domain(url: &[u8]) -> Option<Vec<u8>> {
    let proto_end = url
        .windows(3)
        .position(|w| w == b"://")?;
    let after_proto = &url[proto_end + 3..];

    let host_start = after_proto
        .iter()
        .position(|&b| b == b'@')
        .map(|p| p + 1)
        .unwrap_or(0);
    let host_part = &after_proto[host_start..];

    let host_end = host_part
        .iter()
        .position(|&b| b == b':' || b == b'/' || b == b'?' || b == b'#')
        .unwrap_or(host_part.len());

    let domain = &host_part[..host_end];
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_vec())
    }
}

fn domain_matches_any(domain: &[u8], set: &HashSet<Vec<u8>>) -> bool {
    for pattern in set {
        if domain.len() > pattern.len() {
            let suffix_start = domain.len() - pattern.len();
            if domain[suffix_start..] == **pattern && domain[suffix_start - 1] == b'.' {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_simple() {
        let url = b"https://example.com/path";
        let domain = extract_domain(url).unwrap();
        assert_eq!(&domain, b"example.com");
    }

    #[test]
    fn test_extract_domain_with_port() {
        let url = b"https://example.com:8080/path";
        let domain = extract_domain(url).unwrap();
        assert_eq!(&domain, b"example.com");
    }

    #[test]
    fn test_extract_domain_with_auth() {
        let url = b"https://user:pass@example.com/path";
        let domain = extract_domain(url).unwrap();
        assert_eq!(&domain, b"example.com");
    }

    #[test]
    fn test_extract_domain_subdomain() {
        let url = b"https://sub.example.com/path";
        let domain = extract_domain(url).unwrap();
        assert_eq!(&domain, b"sub.example.com");
    }

    #[test]
    fn test_filter_empty_matches_all() {
        let filter = Filter::new();
        let record = Record {
            line_num: 1,
            url: b"https://anything.com",
            username: b"user",
            password: b"pass",
        };
        assert!(filter.matches(&record));
    }

    #[test]
    fn test_filter_url_pattern() {
        let mut filter = Filter::new();
        filter.add_url_pattern(r"example\.com").unwrap();

        let match_record = Record {
            line_num: 1,
            url: b"https://example.com/login",
            username: b"user",
            password: b"pass",
        };
        let no_match = Record {
            line_num: 1,
            url: b"https://other.com/login",
            username: b"user",
            password: b"pass",
        };

        assert!(filter.matches(&match_record));
        assert!(!filter.matches(&no_match));
    }

    #[test]
    fn test_filter_domain_whitelist() {
        let mut filter = Filter::new();
        filter.set_domain_whitelist(vec!["example.com".to_string()]);

        let match_record = Record {
            line_num: 1,
            url: b"https://example.com/login",
            username: b"user",
            password: b"pass",
        };
        let subdomain_match = Record {
            line_num: 1,
            url: b"https://sub.example.com/login",
            username: b"user",
            password: b"pass",
        };
        let no_match = Record {
            line_num: 1,
            url: b"https://other.com/login",
            username: b"user",
            password: b"pass",
        };

        assert!(filter.matches(&match_record));
        assert!(filter.matches(&subdomain_match));
        assert!(!filter.matches(&no_match));
    }

    #[test]
    fn test_filter_domain_blacklist() {
        let mut filter = Filter::new();
        filter.set_domain_blacklist(vec!["blocked.com".to_string()]);

        let allowed = Record {
            line_num: 1,
            url: b"https://allowed.com/login",
            username: b"user",
            password: b"pass",
        };
        let blocked = Record {
            line_num: 1,
            url: b"https://blocked.com/login",
            username: b"user",
            password: b"pass",
        };

        assert!(filter.matches(&allowed));
        assert!(!filter.matches(&blocked));
    }

    #[test]
    fn test_filter_combined() {
        let mut filter = Filter::new();
        filter.set_domain_whitelist(vec!["example.com".to_string()]);
        filter.add_url_pattern(r"/login").unwrap();

        let full_match = Record {
            line_num: 1,
            url: b"https://example.com/login",
            username: b"user",
            password: b"pass",
        };
        let domain_only = Record {
            line_num: 1,
            url: b"https://example.com/other",
            username: b"user",
            password: b"pass",
        };

        assert!(filter.matches(&full_match));
        assert!(!filter.matches(&domain_only));
    }
}
