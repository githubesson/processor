use std::collections::HashSet;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CredItem {
    pub url: String,
    pub username: String,
    pub password: String,
    pub uuid: String,
    pub dir: String,
}

impl CredItem {
    pub fn new(url: String, username: String, password: String, uuid: String, dir: String) -> Self {
        Self {
            url,
            username,
            password,
            uuid,
            dir,
        }
    }

    pub fn dedup_key(&self) -> (String, String, String) {
        (self.url.clone(), self.username.clone(), self.password.clone())
    }
}

pub fn write_json(items: &[CredItem], path: &Path) -> std::io::Result<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, items)?;
    Ok(())
}

pub fn deduplicate(items: &[CredItem]) -> Vec<CredItem> {
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut unique = Vec::new();

    for item in items {
        let key = item.dedup_key();
        if !seen.contains(&key) {
            seen.insert(key);
            unique.push(item.clone());
        }
    }

    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup() {
        let items = vec![
            CredItem::new(
                "https://example.com".into(),
                "user".into(),
                "pass".into(),
                "uuid1".into(),
                "./dir1".into(),
            ),
            CredItem::new(
                "https://example.com".into(),
                "user".into(),
                "pass".into(),
                "uuid2".into(),
                "./dir2".into(),
            ),
            CredItem::new(
                "https://other.com".into(),
                "user2".into(),
                "pass2".into(),
                "uuid3".into(),
                "./dir3".into(),
            ),
        ];

        let unique = deduplicate(&items);
        assert_eq!(unique.len(), 2);
    }

    #[test]
    fn test_serialize() {
        let item = CredItem::new(
            "https://example.com".into(),
            "user".into(),
            "pass".into(),
            "550e8400-e29b-41d4-a716-446655440000".into(),
            "./logs/192.168.1.1".into(),
        );

        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"url\":\"https://example.com\""));
        assert!(json.contains("\"username\":\"user\""));
        assert!(json.contains("\"password\":\"pass\""));
    }
}
