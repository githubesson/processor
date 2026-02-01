use std::fs::File;
use std::io::{BufWriter, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use memmap2::Mmap;
use rayon::prelude::*;
use thiserror::Error;

use crate::binary::BinaryWriter;
use crate::filter::Filter;
use crate::parser::{parse_mmap, Parser};

#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Binary error: {0}")]
    Binary(#[from] crate::binary::BinaryError),
    #[error("Parse error: {0}")]
    Parse(#[from] crate::parser::ParseError),
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub files_processed: u64,
    pub total_lines: u64,
    pub valid_records: u64,
    pub filtered_records: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

#[derive(Default)]
pub struct AtomicStats {
    pub files_processed: AtomicU64,
    pub total_lines: AtomicU64,
    pub valid_records: AtomicU64,
    pub filtered_records: AtomicU64,
    pub bytes_read: AtomicU64,
    pub bytes_written: AtomicU64,
}

impl AtomicStats {
    pub fn add(&self, stats: &Stats) {
        self.files_processed.fetch_add(stats.files_processed, Ordering::Relaxed);
        self.total_lines.fetch_add(stats.total_lines, Ordering::Relaxed);
        self.valid_records.fetch_add(stats.valid_records, Ordering::Relaxed);
        self.filtered_records.fetch_add(stats.filtered_records, Ordering::Relaxed);
        self.bytes_read.fetch_add(stats.bytes_read, Ordering::Relaxed);
        self.bytes_written.fetch_add(stats.bytes_written, Ordering::Relaxed);
    }

    pub fn to_stats(&self) -> Stats {
        Stats {
            files_processed: self.files_processed.load(Ordering::Relaxed),
            total_lines: self.total_lines.load(Ordering::Relaxed),
            valid_records: self.valid_records.load(Ordering::Relaxed),
            filtered_records: self.filtered_records.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub enum OutputMode {
    Binary(PathBuf),
    Text(PathBuf),
    DryRun,
}

pub fn process_files(
    paths: &[PathBuf],
    filter: Option<&Filter>,
    output: &OutputMode,
    num_jobs: usize,
) -> Result<Stats, ProcessError> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_jobs)
        .build()
        .unwrap();

    let atomic_stats = AtomicStats::default();

    pool.install(|| {
        paths.par_iter().for_each(|path| {
            match process_single_file(path, filter, output) {
                Ok(stats) => atomic_stats.add(&stats),
                Err(e) => eprintln!("Error processing {}: {}", path.display(), e),
            }
        });
    });

    Ok(atomic_stats.to_stats())
}

pub fn process_single_file(
    path: &Path,
    filter: Option<&Filter>,
    output: &OutputMode,
) -> Result<Stats, ProcessError> {
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len();

    if file_size > 64 * 1024 {
        process_file_mmap(path, filter, output, file_size)
    } else {
        process_file_streaming(path, filter, output, file_size)
    }
}

fn process_file_mmap(
    path: &Path,
    filter: Option<&Filter>,
    output: &OutputMode,
    file_size: u64,
) -> Result<Stats, ProcessError> {
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };

    let mut stats = Stats {
        files_processed: 1,
        bytes_read: file_size,
        ..Default::default()
    };

    let records: Vec<_> = parse_mmap(&mmap)
        .map(|r| {
            stats.total_lines += 1;
            stats.valid_records += 1;
            r
        })
        .filter(|r| {
            if let Some(f) = filter {
                let matches = f.matches(r);
                if matches {
                    stats.filtered_records += 1;
                }
                matches
            } else {
                stats.filtered_records += 1;
                true
            }
        })
        .map(|r| r.to_owned())
        .collect();

    match output {
        OutputMode::Binary(dir) => {
            let output_path = make_output_path(path, dir, "ulpb");
            let file = File::create(&output_path)?;
            let mut writer = BinaryWriter::new(BufWriter::new(file), records.len() as u32)?;

            for record in &records {
                writer.write_record(record)?;
            }

            let buf = writer.finish();
            if let Ok(mut inner) = buf.into_inner() {
                stats.bytes_written = inner.stream_position().unwrap_or(0);
            }
        }
        OutputMode::Text(output_path) => {
            let mut file = File::options()
                .create(true)
                .append(true)
                .open(output_path)?;

            for record in &records {
                writeln!(
                    file,
                    "{}:{}:{}",
                    String::from_utf8_lossy(&record.url),
                    String::from_utf8_lossy(&record.username),
                    String::from_utf8_lossy(&record.password)
                )?;
            }
        }
        OutputMode::DryRun => {}
    }

    Ok(stats)
}

fn process_file_streaming(
    path: &Path,
    filter: Option<&Filter>,
    output: &OutputMode,
    file_size: u64,
) -> Result<Stats, ProcessError> {
    let file = File::open(path)?;
    let parser = Parser::new(file);

    let mut stats = Stats {
        files_processed: 1,
        bytes_read: file_size,
        ..Default::default()
    };

    let mut output_writer: Option<Box<dyn Write>> = match output {
        OutputMode::Binary(dir) => {
            let output_path = make_output_path(path, dir, "ulpb");
            let file = File::create(&output_path)?;
            Some(Box::new(BufWriter::new(file)))
        }
        OutputMode::Text(output_path) => {
            let file = File::options()
                .create(true)
                .append(true)
                .open(output_path)?;
            Some(Box::new(BufWriter::new(file)))
        }
        OutputMode::DryRun => None,
    };

    let mut binary_records = Vec::new();

    for result in parser {
        stats.total_lines += 1;

        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        stats.valid_records += 1;

        let matches = if let Some(f) = filter {
            f.matches_owned(&record)
        } else {
            true
        };

        if matches {
            stats.filtered_records += 1;

            match output {
                OutputMode::Binary(_) => {
                    binary_records.push(record);
                }
                OutputMode::Text(_) => {
                    if let Some(ref mut w) = output_writer {
                        writeln!(
                            w,
                            "{}:{}:{}",
                            String::from_utf8_lossy(&record.url),
                            String::from_utf8_lossy(&record.username),
                            String::from_utf8_lossy(&record.password)
                        )?;
                    }
                }
                OutputMode::DryRun => {}
            }
        }
    }

    if let OutputMode::Binary(_) = output {
        if let Some(writer) = output_writer.take() {
            let mut binary_writer = BinaryWriter::new(writer, binary_records.len() as u32)?;
            for record in &binary_records {
                binary_writer.write_record(record)?;
            }
        }
    }

    Ok(stats)
}

fn make_output_path(input: &Path, output_dir: &Path, extension: &str) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default();
    output_dir.join(format!("{}.{}", stem.to_string_lossy(), extension))
}

pub fn collect_input_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut files = Vec::new();

    for path in paths {
        if path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() && path.extension().map_or(false, |e| e == "txt") {
                    files.push(path);
                }
            }
        } else if path.is_file() {
            files.push(path.clone());
        }
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_process_single_file_dry_run() {
        let temp = TempDir::new().unwrap();
        let content = "https://example.com:user:pass\nhttps://test.com:admin:secret\n";
        let path = create_test_file(temp.path(), "test.txt", content);

        let stats = process_single_file(&path, None, &OutputMode::DryRun).unwrap();

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.valid_records, 2);
        assert_eq!(stats.filtered_records, 2);
    }

    #[test]
    fn test_process_with_filter() {
        let temp = TempDir::new().unwrap();
        let content = "https://example.com:user:pass\nhttps://other.com:admin:secret\n";
        let path = create_test_file(temp.path(), "test.txt", content);

        let mut filter = Filter::new();
        filter.set_domain_whitelist(vec!["example.com".to_string()]);

        let stats = process_single_file(&path, Some(&filter), &OutputMode::DryRun).unwrap();

        assert_eq!(stats.valid_records, 2);
        assert_eq!(stats.filtered_records, 1);
    }

    #[test]
    fn test_collect_input_files() {
        let temp = TempDir::new().unwrap();
        create_test_file(temp.path(), "a.txt", "content");
        create_test_file(temp.path(), "b.txt", "content");
        create_test_file(temp.path(), "c.log", "content");

        let paths = vec![temp.path().to_path_buf()];
        let files = collect_input_files(&paths).unwrap();

        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_make_output_path() {
        let input = Path::new("/data/credentials.txt");
        let output_dir = Path::new("/output");
        let result = make_output_path(input, output_dir, "ulpb");
        assert_eq!(result, PathBuf::from("/output/credentials.ulpb"));
    }
}
