use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Command-line arguments for RustGuard
#[derive(Parser, Debug)]
#[command(name = "rustguard")]
#[command(about = "Unified security scanning tool written in Rust", long_about = None)]
pub struct CliArgs {
    /// Target path to scan
    #[arg(value_name = "PATH")]
    pub target: PathBuf,

    /// Scan mode (dependencies, image, secrets, config, or all)
    #[arg(short, long, default_value = "all")]
    pub mode: ScanMode,

    /// Output format (pretty, json, or sarif)
    #[arg(short, long, default_value = "pretty")]
    pub output: OutputFormat,

    /// Number of parallel jobs
    #[arg(short, long, default_value_t = num_cpus::get())]
    pub jobs: usize,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    Dependencies,
    Image,
    Secrets,
    Config,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Pretty,
    Json,
    Sarif,
}

impl From<&str> for ScanMode {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "dependencies" | "deps" => Self::Dependencies,
            "image" => Self::Image,
            "secrets" => Self::Secrets,
            "config" => Self::Config,
            "all" => Self::All,
            _ => panic!("Invalid scan mode: {}", s),
        }
    }
}

impl From<&str> for OutputFormat {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pretty" => Self::Pretty,
            "json" => Self::Json,
            "sarif" => Self::Sarif,
            _ => panic!("Invalid output format: {}", s),
        }
    }
}

/// Runtime configuration for RustGuard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub scan_mode: ScanMode,
    pub output_format: OutputFormat,
    pub parallel_jobs: usize,
    pub verbose: bool,
    pub target_path: PathBuf,
}

impl From<CliArgs> for RuntimeConfig {
    fn from(args: CliArgs) -> Self {
        Self {
            scan_mode: args.mode,
            output_format: args.output,
            parallel_jobs: args.jobs,
            verbose: args.verbose,
            target_path: args.target,
        }
    }
}

/// Configuration builder for RustGuard
pub struct ConfigBuilder {
    config: RuntimeConfig,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: RuntimeConfig {
                scan_mode: ScanMode::All,
                output_format: OutputFormat::Pretty,
                parallel_jobs: num_cpus::get(),
                verbose: false,
                target_path: PathBuf::from("."),
            },
        }
    }

    pub fn scan_mode(mut self, mode: ScanMode) -> Self {
        self.config.scan_mode = mode;
        self
    }

    pub fn output_format(mut self, format: OutputFormat) -> Self {
        self.config.output_format = format;
        self
    }

    pub fn parallel_jobs(mut self, jobs: usize) -> Self {
        self.config.parallel_jobs = jobs;
        self
    }

    pub fn verbose(mut self, verbose: bool) -> Self {
        self.config.verbose = verbose;
        self
    }

    pub fn target_path(mut self, path: PathBuf) -> Self {
        self.config.target_path = path;
        self
    }

    pub fn build(self) -> RuntimeConfig {
        self.config
    }
}
