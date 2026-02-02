use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use walkdir::WalkDir;

fn get_7z_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let local_7z = exe_dir.join("7z.exe");
                if local_7z.exists() {
                    return local_7z;
                }
            }
        }
    }
    PathBuf::from("7z")
}

#[cfg(not(windows))]
fn get_unrar_path() -> PathBuf {
    PathBuf::from("unrar")
}

const ARCHIVE_EXTENSIONS: &[&str] = &[".zip", ".7z", ".rar", ".tar", ".gz", ".tar.gz", ".tgz"];
const ARCHIVE_PATTERNS: &[&str] = &[
    ".zip",
    ".7z",
    ".rar",
    ".tar",
    ".gz",
    ".tar.gz",
    ".tgz",
    ".zip.*",
    ".7z.*",
    ".rar.*",
    ".tar.*",
    ".gz.*",
    ".tar.gz.*",
    ".tgz.*",
    ".part*.rar",
    ".z??",
    ".r??",
];

const TARGET_FILES: &[&str] = &[
    "passwords.txt",
    "all passwords.txt",
    "_allpasswords_list.txt",
    "password.txt",
    "all_passwords.txt",
    "discordtokens.txt",
    "tokens.txt",
];

const MAX_RECURSION_DEPTH: usize = 10;

pub type ExtractResult<T> = Result<T, ExtractError>;

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("7z command failed: {0}")]
    SevenZipFailed(String),

    #[cfg(windows)]
    #[error("7z not found. Place 7z.exe next to this executable, or install 7z and add to PATH.")]
    SevenZipNotFound,

    #[cfg(not(windows))]
    #[error("7z not found in PATH. Please install 7z and ensure it's in your PATH.")]
    SevenZipNotFound,

    #[cfg(not(windows))]
    #[error("unrar command failed: {0}")]
    UnrarFailed(String),

    #[cfg(not(windows))]
    #[error("unrar not found in PATH. Please install unrar and ensure it's in your PATH.")]
    UnrarNotFound,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Archive not found: {0}")]
    ArchiveNotFound(PathBuf),
}

#[cfg(not(windows))]
fn is_rar(path: &Path) -> bool {
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
    name.to_lowercase().ends_with(".rar")
}

pub fn is_archive(path: &Path) -> bool {
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
    let lower = name.to_lowercase();
    if let Some(part) = rar_part_number(&lower) {
        return part == 1;
    }

    ARCHIVE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) || is_multipart_first_part(&lower)
}

fn is_multipart_first_part(name: &str) -> bool {
    is_rar_part_first(name)
        || ARCHIVE_EXTENSIONS
            .iter()
            .any(|ext| is_numbered_first_part(name, ext))
}

fn is_numbered_first_part(name: &str, base_ext: &str) -> bool {
    if let Some((before_digits, digits)) = name.rsplit_once('.') {
        if before_digits.ends_with(base_ext) && digits.chars().all(|c| c.is_ascii_digit()) {
            return digits.parse::<u32>().ok() == Some(1);
        }
    }
    false
}

fn is_rar_part_first(name: &str) -> bool {
    rar_part_number(name) == Some(1)
}

fn rar_part_number(name: &str) -> Option<u32> {
    let without_rar = name.strip_suffix(".rar")?;
    let (_, digits) = without_rar.rsplit_once(".part")?;
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    digits.parse::<u32>().ok()
}

#[derive(Debug, Clone, Default)]
pub struct ExtractOptions<'a> {
    pub password: Option<&'a str>,
    pub threads: Option<usize>,
}

pub fn extract_archive(
    archive_path: &Path,
    output_dir: &Path,
    opts: &ExtractOptions,
) -> ExtractResult<()> {
    if !archive_path.exists() {
        return Err(ExtractError::ArchiveNotFound(archive_path.to_path_buf()));
    }

    fs::create_dir_all(output_dir)?;

    #[cfg(windows)]
    {
        extract_with_7z(archive_path, output_dir, opts)
    }

    #[cfg(not(windows))]
    {
        if is_rar(archive_path) {
            extract_with_unrar(archive_path, output_dir, opts)
        } else {
            extract_with_7z(archive_path, output_dir, opts)
        }
    }
}

#[cfg(not(windows))]
fn extract_with_unrar(
    archive_path: &Path,
    output_dir: &Path,
    opts: &ExtractOptions,
) -> ExtractResult<()> {
    let mut cmd = Command::new(get_unrar_path());
    cmd.args(["x", "-o+"]);

    if let Some(pw) = opts.password {
        cmd.arg(format!("-p{}", pw));
    }

    if let Some(threads) = opts.threads {
        cmd.arg(format!("-mt{}", threads));
    }

    for target in TARGET_FILES {
        cmd.arg(format!("-n*{}", target));
    }

    for ext in ARCHIVE_PATTERNS {
        cmd.arg(format!("-n*{}", ext));
    }

    cmd.arg(archive_path);
    cmd.arg(format!("{}/", output_dir.display()));

    let output = cmd.output();

    match output {
        Ok(result) => {
            if result.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr);
                let stdout = String::from_utf8_lossy(&result.stdout);
                if has_content(output_dir)
                    || stderr.contains("No files to extract")
                    || stdout.contains("No files to extract")
                {
                    if !stderr.is_empty() && !stderr.contains("No files to extract") {
                        eprintln!("unrar warning (continuing): {}", stderr);
                    }
                    Ok(())
                } else {
                    Err(ExtractError::UnrarFailed(format!(
                        "stdout: {}\nstderr: {}",
                        stdout, stderr
                    )))
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ExtractError::UnrarNotFound),
        Err(e) => Err(ExtractError::Io(e)),
    }
}

fn extract_with_7z(
    archive_path: &Path,
    output_dir: &Path,
    opts: &ExtractOptions,
) -> ExtractResult<()> {
    let output_arg = format!("-o{}", output_dir.display());

    let mut cmd = Command::new(get_7z_path());
    cmd.args(["x", &output_arg, "-y"]);

    if let Some(pw) = opts.password {
        cmd.arg(format!("-p{}", pw));
    }

    if let Some(threads) = opts.threads {
        cmd.arg(format!("-mmt={}", threads));
    }

    cmd.arg(archive_path);

    for target in TARGET_FILES {
        cmd.arg(format!("-ir!{}", target));
    }

    for ext in ARCHIVE_PATTERNS {
        cmd.arg(format!("-ir!*{}", ext));
    }

    let output = cmd.output();

    match output {
        Ok(result) => {
            if result.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr);
                let stdout = String::from_utf8_lossy(&result.stdout);
                if has_content(output_dir)
                    || stderr.contains("No files to process")
                    || stdout.contains("No files to process")
                {
                    if !stderr.is_empty() && !stderr.contains("No files to process") {
                        eprintln!("7z warning (continuing): {}", stderr);
                    }
                    Ok(())
                } else {
                    Err(ExtractError::SevenZipFailed(format!(
                        "stdout: {}\nstderr: {}",
                        stdout, stderr
                    )))
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ExtractError::SevenZipNotFound),
        Err(e) => Err(ExtractError::Io(e)),
    }
}

fn has_content(dir: &Path) -> bool {
    if let Ok(mut entries) = fs::read_dir(dir) {
        entries.next().is_some()
    } else {
        false
    }
}

pub fn collect_archives(dir: &Path) -> Vec<PathBuf> {
    let mut archives = Vec::new();

    for entry in WalkDir::new(dir)
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() && is_archive(path) {
            archives.push(path.to_path_buf());
        }
    }

    archives
}

pub fn recursive_extract(dir: &Path, opts: &ExtractOptions) -> ExtractResult<()> {
    for depth in 0..MAX_RECURSION_DEPTH {
        let archives = collect_archives(dir);

        if archives.is_empty() {
            break;
        }

        eprintln!(
            "Extraction depth {}: found {} archive(s)",
            depth + 1,
            archives.len()
        );

        for archive_path in archives {
            let extract_dir = archive_path.parent().unwrap_or(dir);

            match extract_archive(&archive_path, extract_dir, opts) {
                Ok(()) => {
                    if let Err(e) = fs::remove_file(&archive_path) {
                        eprintln!(
                            "Warning: could not delete {}: {}",
                            archive_path.display(),
                            e
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: failed to extract {}: {}",
                        archive_path.display(),
                        e
                    );
                    let _ = fs::remove_file(&archive_path);
                }
            }
        }
    }

    Ok(())
}

pub fn extract_all(
    archive_path: &Path,
    output_dir: &Path,
    opts: &ExtractOptions,
) -> ExtractResult<PathBuf> {
    let archive_name = archive_path
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("extracted");

    let extract_dir = output_dir.join(archive_name);
    fs::create_dir_all(&extract_dir)?;

    eprintln!(
        "Extracting {} to {}",
        archive_path.display(),
        extract_dir.display()
    );

    extract_archive(archive_path, &extract_dir, opts)?;
    recursive_extract(&extract_dir, opts)?;

    Ok(extract_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_archive() {
        assert!(is_archive(Path::new("test.zip")));
        assert!(is_archive(Path::new("test.ZIP")));
        assert!(is_archive(Path::new("test.7z")));
        assert!(is_archive(Path::new("test.rar")));
        assert!(is_archive(Path::new("test.tar.gz")));
        assert!(is_archive(Path::new("test.zip.001")));
        assert!(is_archive(Path::new("test.7z.001")));
        assert!(is_archive(Path::new("test.tar.gz.001")));
        assert!(is_archive(Path::new("test.tgz.001")));
        assert!(is_archive(Path::new("test.part1.rar")));
        assert!(is_archive(Path::new("test.part01.rar")));
        assert!(!is_archive(Path::new("test.txt")));
        assert!(!is_archive(Path::new("test.json")));
        assert!(!is_archive(Path::new("test.zip.002")));
        assert!(!is_archive(Path::new("test.part2.rar")));
        assert!(!is_archive(Path::new("test.z01")));
    }
}
