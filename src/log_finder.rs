use std::collections::HashMap;
use std::path::{Path, PathBuf};

use uuid::Uuid;
use walkdir::WalkDir;

const TARGET_FILES: &[&str] = &[
    "passwords.txt",
    "all passwords.txt",
    "_allpasswords_list.txt",
    "password.txt",
    "all_passwords.txt",
];

pub fn is_target_file(name: &str) -> bool {
    let lower = name.to_lowercase();
    TARGET_FILES.iter().any(|t| lower == *t)
}

pub fn find_password_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if is_target_file(name) {
                    files.push(path.to_path_buf());
                }
            }
        }
    }

    files
}

#[derive(Debug, Clone)]
pub struct LogRoot {
    pub path: PathBuf,
    pub uuid: String,
    pub relative_path: String,
}

pub fn analyze_log_structure(base_dir: &Path, password_files: &[PathBuf]) -> Vec<LogRoot> {
    if password_files.is_empty() {
        return Vec::new();
    }

    let mut depth_counts: HashMap<usize, HashMap<PathBuf, usize>> = HashMap::new();

    for file in password_files {
        if let Ok(relative) = file.strip_prefix(base_dir) {
            let components: Vec<_> = relative.components().collect();
            for depth in 0..components.len().saturating_sub(1) {
                let partial: PathBuf = components[..=depth].iter().collect();
                let full_path = base_dir.join(&partial);
                *depth_counts
                    .entry(depth)
                    .or_default()
                    .entry(full_path)
                    .or_insert(0) += 1;
            }
        }
    }

    let best_depth = depth_counts
        .iter()
        .max_by_key(|(_, dirs)| dirs.len())
        .map(|(depth, _)| *depth);

    match best_depth {
        Some(depth) => {
            let dirs = depth_counts.get(&depth).unwrap();
            dirs.keys()
                .map(|path| {
                    let uuid = Uuid::new_v4().to_string();
                    let relative = path
                        .strip_prefix(base_dir)
                        .map(|p| format!("./{}", p.display()))
                        .unwrap_or_else(|_| path.display().to_string());
                    LogRoot {
                        path: path.clone(),
                        uuid,
                        relative_path: relative,
                    }
                })
                .collect()
        }
        None => {
            vec![LogRoot {
                path: base_dir.to_path_buf(),
                uuid: Uuid::new_v4().to_string(),
                relative_path: ".".to_string(),
            }]
        }
    }
}

pub fn map_files_to_roots(
    password_files: &[PathBuf],
    log_roots: &[LogRoot],
) -> HashMap<PathBuf, LogRoot> {
    let mut mapping = HashMap::new();

    for file in password_files {
        let best_root = log_roots
            .iter()
            .filter(|root| file.starts_with(&root.path))
            .max_by_key(|root| root.path.components().count());

        if let Some(root) = best_root {
            mapping.insert(file.clone(), root.clone());
        }
    }

    mapping
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_file_matching() {
        let names = ["passwords.txt", "PASSWORDS.TXT", "Passwords.Txt"];
        for name in names {
            let lower = name.to_lowercase();
            assert!(TARGET_FILES.iter().any(|t| lower == *t));
        }
    }
}
