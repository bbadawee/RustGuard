use std::sync::Arc;
use anyhow::Result;
use serde::Serialize;

pub mod error;
pub mod scan;
pub mod types;

/// Core scanning context that orchestrates different scanning operations
pub struct ScannerContext {
    pub config: Arc<ScanConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanConfig {
    pub output_format: OutputFormat,
    pub parallel_jobs: usize,
    pub verbose: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum OutputFormat {
    Pretty,
    Json,
    Sarif,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            output_format: OutputFormat::Pretty,
            parallel_jobs: num_cpus::get(),
            verbose: false,
        }
    }
}

impl ScannerContext {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub async fn scan(&self, target: &str) -> Result<Vec<ScanResult>> {
        // TODO: Implement scan orchestration
        Ok(vec![])
    }
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub target: String,
    pub issues: Vec<Issue>,
    pub scan_time: std::time::Duration,
}

#[derive(Debug, Serialize)]
pub struct Issue {
    pub severity: Severity,
    pub description: String,
    pub location: Option<String>,
    pub fix: Option<String>,
}

#[derive(Debug, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
