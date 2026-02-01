pub mod binary;
pub mod block_parser;
pub mod extractor;
pub mod filter;
pub mod json_output;
pub mod log_finder;
pub mod parallel;
pub mod parser;
pub mod record;

pub use binary::{BinaryReader, BinaryWriter};
pub use block_parser::{parse_password_file, parse_password_file_reader, BlockRecord};
pub use extractor::{extract_all, extract_archive, is_archive, ExtractError, ExtractOptions};
pub use filter::Filter;
pub use json_output::{deduplicate, write_json, CredItem};
pub use log_finder::{analyze_log_structure, find_password_files, is_target_file, map_files_to_roots, LogRoot};
pub use parallel::{collect_input_files, process_files, process_single_file, OutputMode, Stats};
pub use parser::{parse_line, parse_mmap, Parser};
pub use record::{OwnedRecord, Record};
