use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;

use clap::{Args, Parser as ClapParser, Subcommand};
use rayon::prelude::*;
use uuid::Uuid;

use ulp_parser::{
    analyze_log_structure, collect_input_files, deduplicate, extract_all, find_password_files,
    is_archive, map_files_to_roots, parse_password_file, process_files, write_json, BinaryReader,
    CredItem, ExtractOptions, Filter, OutputMode, Stats,
};

#[derive(ClapParser)]
#[command(name = "ulp-parser")]
#[command(about = "High-performance parser for ULP credential log files")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Parse(ParseArgs),
    Extract(ExtractArgs),
    ToText {
        #[arg(value_name = "FILE")]
        input: PathBuf,

        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    Info {
        #[arg(value_name = "FILE")]
        input: PathBuf,
    },
    Validate {
        #[arg(value_name = "INPUT", required = true)]
        inputs: Vec<PathBuf>,

        #[arg(short, long, value_name = "N")]
        jobs: Option<usize>,
    },
}

#[derive(Args)]
struct ParseArgs {
    #[arg(value_name = "INPUT", required = true)]
    inputs: Vec<PathBuf>,

    #[arg(short, long, value_name = "DIR")]
    output: Option<PathBuf>,

    #[arg(short, long, value_name = "PATTERN")]
    filter: Vec<String>,

    #[arg(short, long, value_name = "DOMAIN")]
    domain: Vec<String>,

    #[arg(long, value_name = "DOMAIN")]
    exclude_domain: Vec<String>,

    #[arg(short, long, value_name = "N")]
    jobs: Option<usize>,

    #[arg(short, long)]
    stats: bool,

    #[arg(long)]
    text: bool,
}

#[derive(Args)]
struct ExtractArgs {
    #[arg(value_name = "ARCHIVE")]
    archive: PathBuf,

    #[arg(short, long, value_name = "DIR")]
    output: Option<PathBuf>,

    #[arg(short, long, value_name = "PASSWORD")]
    password: Option<String>,

    #[arg(short, long, value_name = "N")]
    jobs: Option<usize>,

    #[arg(short, long)]
    stats: bool,

    #[arg(long)]
    keep_archive: bool,

    #[arg(long)]
    txt: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse(args) => {
            cmd_process(&args)?;
        }
        Commands::Extract(args) => {
            cmd_extract(&args)?;
        }
        Commands::ToText { input, output } => {
            cmd_to_text(&input, output.as_deref())?;
        }
        Commands::Info { input } => {
            cmd_info(&input)?;
        }
        Commands::Validate { inputs, jobs } => {
            cmd_validate(&inputs, jobs)?;
        }
    }

    Ok(())
}

fn cmd_process(args: &ParseArgs) -> Result<(), Box<dyn std::error::Error>> {
    let files = collect_input_files(&args.inputs)?;
    if files.is_empty() {
        eprintln!("No input files found");
        return Ok(());
    }

    let filter = build_filter(&args.filter, &args.domain, &args.exclude_domain)?;

    let output_mode = if let Some(ref dir) = args.output {
        std::fs::create_dir_all(dir)?;
        if args.text {
            OutputMode::Text(dir.join("output.txt"))
        } else {
            OutputMode::Binary(dir.clone())
        }
    } else {
        OutputMode::DryRun
    };

    let num_jobs = args.jobs.unwrap_or_else(num_cpus::get);
    let filter_ref = if filter.is_empty() { None } else { Some(&filter) };

    eprintln!("Processing {} files with {} threads...", files.len(), num_jobs);

    let stats = process_files(&files, filter_ref, &output_mode, num_jobs)?;

    if args.stats || matches!(output_mode, OutputMode::DryRun) {
        print_stats(&stats);
    }

    Ok(())
}

fn cmd_extract(args: &ExtractArgs) -> Result<(), Box<dyn std::error::Error>> {
    if !args.archive.exists() {
        return Err(format!("Archive not found: {}", args.archive.display()).into());
    }

    if !is_archive(&args.archive) {
        return Err(format!(
            "Not a recognized archive format: {}",
            args.archive.display()
        )
        .into());
    }

    let output_dir = args.output.clone().unwrap_or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."))
    });

    std::fs::create_dir_all(&output_dir)?;

    eprintln!("Extracting archive: {}", args.archive.display());
    let extract_opts = ExtractOptions {
        password: args.password.as_deref(),
        threads: args.jobs,
    };
    let extract_dir = extract_all(&args.archive, &output_dir, &extract_opts)?;

    eprintln!("Searching for password files...");
    let password_files = find_password_files(&extract_dir);

    if password_files.is_empty() {
        eprintln!("No password files found in archive");
        return Ok(());
    }

    eprintln!("Found {} password file(s)", password_files.len());

    let log_roots = analyze_log_structure(&extract_dir, &password_files);
    let file_to_root = map_files_to_roots(&password_files, &log_roots);

    eprintln!("Identified {} log root(s)", log_roots.len());

    let num_threads = args.jobs.unwrap_or_else(num_cpus::get);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();

    eprintln!("Parsing {} file(s) with {} threads...", password_files.len(), num_threads);

    let results: Vec<_> = pool.install(|| {
        password_files
            .par_iter()
            .filter_map(|file_path| {
                let root = file_to_root.get(file_path);
                let (uuid, dir) = match root {
                    Some(r) => (r.uuid.clone(), r.relative_path.clone()),
                    None => (Uuid::new_v4().to_string(), ".".to_string()),
                };

                match std::fs::read(file_path) {
                    Ok(bytes) => {
                        let content = String::from_utf8_lossy(&bytes);
                        let records = parse_password_file(&content);
                        let items: Vec<CredItem> = records
                            .into_iter()
                            .map(|record| {
                                CredItem::new(
                                    record.url,
                                    record.username,
                                    record.password,
                                    uuid.clone(),
                                    dir.clone(),
                                )
                            })
                            .collect();
                        Some(items)
                    }
                    Err(e) => {
                        eprintln!("Warning: could not read {}: {}", file_path.display(), e);
                        None
                    }
                }
            })
            .collect()
    });

    let files_processed = results.len();
    let combined_items: Vec<CredItem> = results.into_iter().flatten().collect();
    let valid_records = combined_items.len();

    let unique_items = deduplicate(&combined_items);

    let unique_path = extract_dir.join("unique.json");
    let combined_path = extract_dir.join("combined.json");

    write_json(&unique_items, &unique_path)?;
    write_json(&combined_items, &combined_path)?;

    eprintln!("\nOutput written:");
    eprintln!("  unique.json:   {} records", unique_items.len());
    eprintln!("  combined.json: {} records", combined_items.len());

    if args.txt {
        let txt_path = extract_dir.join("unique.txt");
        let mut txt_file = File::create(&txt_path)?;
        for item in &unique_items {
            writeln!(txt_file, "{}:{}:{}", item.url, item.username, item.password)?;
        }
        eprintln!("  unique.txt:    {} records", unique_items.len());
    }

    if !args.keep_archive {
        if let Err(e) = std::fs::remove_file(&args.archive) {
            eprintln!("Warning: could not delete archive: {}", e);
        }
    }

    if args.stats {
        eprintln!("\n--- Statistics ---");
        eprintln!("Files processed:   {}", files_processed);
        eprintln!("Records parsed:    {}", valid_records);
        eprintln!("Combined records:  {}", combined_items.len());
        eprintln!("Unique records:    {}", unique_items.len());
        let dedup_pct = if !combined_items.is_empty() {
            (1.0 - (unique_items.len() as f64 / combined_items.len() as f64)) * 100.0
        } else {
            0.0
        };
        eprintln!("Duplicates removed: {:.1}%", dedup_pct);
    }

    eprintln!("\nExtraction complete: {}", extract_dir.display());

    Ok(())
}

fn cmd_to_text(input: &PathBuf, output: Option<&std::path::Path>) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(input)?;
    let reader = BinaryReader::new(BufReader::new(file))?;

    let mut writer: Box<dyn Write> = if let Some(path) = output {
        Box::new(BufWriter::new(File::create(path)?))
    } else {
        Box::new(std::io::stdout().lock())
    };

    for result in reader {
        let record = result?;
        writeln!(
            writer,
            "{}:{}:{}",
            String::from_utf8_lossy(&record.url),
            String::from_utf8_lossy(&record.username),
            String::from_utf8_lossy(&record.password)
        )?;
    }

    Ok(())
}

fn cmd_info(input: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(input)?;
    let reader = BinaryReader::new(BufReader::new(file))?;
    let header = reader.header();

    println!("File: {}", input.display());
    println!("Version: {}", header.version);
    println!("Record count: {}", header.record_count);
    println!("Compressed: {}", header.flags.compressed());

    Ok(())
}

fn cmd_validate(inputs: &[PathBuf], jobs: Option<usize>) -> Result<(), Box<dyn std::error::Error>> {
    let files = collect_input_files(inputs)?;
    if files.is_empty() {
        eprintln!("No input files found");
        return Ok(());
    }

    let num_jobs = jobs.unwrap_or_else(num_cpus::get);
    eprintln!("Validating {} files with {} threads...", files.len(), num_jobs);

    let stats = process_files(&files, None, &OutputMode::DryRun, num_jobs)?;
    print_stats(&stats);

    let invalid = stats.total_lines - stats.valid_records;
    if invalid > 0 {
        eprintln!("\nWarning: {} invalid lines found", invalid);
    }

    Ok(())
}

fn build_filter(
    patterns: &[String],
    domains: &[String],
    exclude_domains: &[String],
) -> Result<Filter, regex::Error> {
    let mut filter = Filter::new();

    for pattern in patterns {
        filter.add_url_pattern(pattern)?;
    }

    if !domains.is_empty() {
        filter.set_domain_whitelist(domains.to_vec());
    }

    if !exclude_domains.is_empty() {
        filter.set_domain_blacklist(exclude_domains.to_vec());
    }

    Ok(filter)
}

fn print_stats(stats: &Stats) {
    eprintln!("\n--- Statistics ---");
    eprintln!("Files processed:   {}", stats.files_processed);
    eprintln!("Total lines:       {}", stats.total_lines);
    eprintln!("Valid records:     {}", stats.valid_records);
    eprintln!("Filtered records:  {}", stats.filtered_records);
    eprintln!("Bytes read:        {} ({:.2} MB)",
        stats.bytes_read,
        stats.bytes_read as f64 / 1_048_576.0
    );
    if stats.bytes_written > 0 {
        eprintln!("Bytes written:     {} ({:.2} MB)",
            stats.bytes_written,
            stats.bytes_written as f64 / 1_048_576.0
        );
    }

    if stats.total_lines > 0 {
        let valid_pct = (stats.valid_records as f64 / stats.total_lines as f64) * 100.0;
        eprintln!("Parse success:     {:.1}%", valid_pct);
    }
}

mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4)
    }
}
