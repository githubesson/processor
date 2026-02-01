use std::io::Read;

#[derive(Debug, Clone, Default)]
pub struct BlockRecord {
    pub url: String,
    pub username: String,
    pub password: String,
}

impl BlockRecord {
    pub fn is_empty(&self) -> bool {
        self.url.is_empty() && self.username.is_empty() && self.password.is_empty()
    }
}

fn normalize_key(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .replace(' ', "")
        .replace('-', "")
        .replace('_', "")
}

fn is_site_key(k: &str) -> bool {
    matches!(
        k,
        "url" | "uri" | "link" | "originurl" | "host" | "hostname" | "site" | "website"
            | "domain" | "address" | "webaddress" | "page" | "loginpage" | "homepage"
    )
}

fn is_user_key(k: &str) -> bool {
    matches!(
        k,
        "user" | "username" | "login" | "usernameemail" | "email" | "emailaddress"
            | "mail" | "account" | "acc" | "loginname" | "loginid" | "useridname"
            | "phone" | "phonenumber" | "mobile"
    )
}

fn is_pass_key(k: &str) -> bool {
    matches!(
        k,
        "password" | "pass" | "passwd" | "pwd" | "pin" | "pincode" | "passcode"
    )
}

fn is_separator_line(line: &str) -> bool {
    let t = line.trim();
    if t.len() < 3 {
        return false;
    }
    let first = t.chars().next().unwrap();
    if first != '-' && first != '_' && first != '~' && first != '=' {
        return false;
    }
    t.chars().all(|c| c == first)
}

fn is_repeated_char_line(line: &str) -> bool {
    let t = line.trim();
    if t.len() < 3 {
        return false;
    }
    let first = t.chars().next().unwrap();
    t.chars().all(|c| c == first)
}

fn clean_leading_label(mut s: String) -> String {
    s = s.trim().to_string();
    for _ in 0..5 {
        if let Some(idx) = s.find(':') {
            if idx == 0 {
                break;
            }
            let left = normalize_key(&s[..idx]);
            if is_site_key(&left) || is_user_key(&left) || is_pass_key(&left) {
                s = s[idx + 1..].trim().to_string();
                continue;
            }
        }
        break;
    }
    s
}

fn split_into_blocks(content: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current_block = Vec::new();

    for line in content.lines() {
        if is_separator_line(line) {
            let block = current_block.join("\n").trim().to_string();
            if !block.is_empty() {
                blocks.push(block);
            }
            current_block.clear();
        } else {
            current_block.push(line);
        }
    }

    let block = current_block.join("\n").trim().to_string();
    if !block.is_empty() {
        blocks.push(block);
    }

    blocks
}

fn detect_trigger_field(content: &str) -> &'static str {
    let blocks = split_into_blocks(content);
    let mut last_field_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

    for block in &blocks {
        let mut last_field = "";
        for line in block.lines() {
            let ln = line.trim();
            if ln.is_empty() {
                continue;
            }
            if let Some(idx) = ln.find(':') {
                if idx == 0 {
                    continue;
                }
                let key = normalize_key(&ln[..idx]);
                let val = ln[idx + 1..].trim();

                if is_site_key(&key) {
                    last_field = "site";
                } else if is_user_key(&key) && !val.is_empty() {
                    last_field = "user";
                } else if is_pass_key(&key) {
                    last_field = "pass";
                }
            }
        }
        if !last_field.is_empty() {
            *last_field_counts.entry(last_field).or_insert(0) += 1;
        }
    }

    last_field_counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(field, _)| field)
        .unwrap_or("pass")
}

fn parse_block(block: &str, trigger_field: &str) -> Vec<BlockRecord> {
    let mut records = Vec::new();
    let mut current = BlockRecord::default();

    let flush = |cur: &mut BlockRecord, records: &mut Vec<BlockRecord>| {
        if cur.is_empty() {
            return;
        }
        let lc = cur.password.trim().to_lowercase();
        if lc.starts_with("application:") {
            *cur = BlockRecord::default();
            return;
        }
        records.push(std::mem::take(cur));
    };

    for line in block.lines() {
        let ln = line.trim();
        if ln.is_empty() {
            continue;
        }

        let lnl = ln.to_lowercase();
        if lnl.starts_with("browser:") || lnl.starts_with("web browser:") || lnl.starts_with("webbrowser:") {
            continue;
        }

        if is_repeated_char_line(ln) {
            continue;
        }

        let idx = match ln.find(':') {
            Some(i) if i > 0 => i,
            _ => continue,
        };

        let key = normalize_key(&ln[..idx]);
        let val = ln[idx + 1..].trim().to_string();
        let val = clean_leading_label(val);

        let is_pass = is_pass_key(&key);

        if val.is_empty() && !is_pass {
            continue;
        }

        if is_site_key(&key) {
            current.url = val;
            if trigger_field == "site" {
                flush(&mut current, &mut records);
            }
        } else if is_user_key(&key) {
            current.username = val;
            if trigger_field == "user" {
                flush(&mut current, &mut records);
            }
        } else if is_pass_key(&key) {
            current.password = val;
            if trigger_field == "pass" {
                flush(&mut current, &mut records);
            }
        }
    }

    flush(&mut current, &mut records);

    records
}

pub fn parse_password_file(content: &str) -> Vec<BlockRecord> {
    let trigger_field = detect_trigger_field(content);
    let blocks = split_into_blocks(content);

    let mut all_records = Vec::new();
    for block in blocks {
        let records = parse_block(&block, trigger_field);
        all_records.extend(records);
    }

    all_records
}

pub fn parse_password_file_reader<R: Read>(mut reader: R) -> std::io::Result<Vec<BlockRecord>> {
    let mut content = String::new();
    reader.read_to_string(&mut content)?;
    Ok(parse_password_file(&content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_block() {
        let content = r#"
URL: https://example.com/login
Username: user@example.com
Password: mypassword123
"#;
        let records = parse_password_file(content);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].url, "https://example.com/login");
        assert_eq!(records[0].username, "user@example.com");
        assert_eq!(records[0].password, "mypassword123");
    }

    #[test]
    fn test_multiple_blocks() {
        let content = r#"
URL: https://example.com
Username: user1
Password: pass1
===========================
URL: https://other.com
Username: user2
Password: pass2
"#;
        let records = parse_password_file(content);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].url, "https://example.com");
        assert_eq!(records[1].url, "https://other.com");
    }

    #[test]
    fn test_with_browser_line() {
        let content = r#"
Browser: Chrome
URL: https://example.com
Username: user
Password: pass
"#;
        let records = parse_password_file(content);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].url, "https://example.com");
    }

    #[test]
    fn test_normalize_key() {
        assert_eq!(normalize_key("User Name"), "username");
        assert_eq!(normalize_key("Pass-Word"), "password");
        assert_eq!(normalize_key("  URL  "), "url");
    }

    #[test]
    fn test_is_separator() {
        assert!(is_separator_line("========"));
        assert!(is_separator_line("--------"));
        assert!(is_separator_line("~~~~~~~~"));
        assert!(!is_separator_line("abc"));
        assert!(!is_separator_line("=="));
    }

    #[test]
    fn test_clean_leading_label() {
        assert_eq!(clean_leading_label("URL: https://example.com".to_string()), "https://example.com");
        assert_eq!(clean_leading_label("Username: Password: actualpass".to_string()), "actualpass");
    }
}
