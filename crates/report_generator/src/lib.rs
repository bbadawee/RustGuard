use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub mod formats;
pub mod statistics;

/// Report configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportConfig {
    pub output_format: OutputFormat,
    pub include_details: bool,
    pub include_statistics: bool,
    pub include_metadata: bool,
    pub show_severity: bool,
    pub show_location: bool,
    pub show_fixes: bool,
    pub group_by: Option<GroupBy>,
    pub sort_by: Option<SortBy>,
    pub filter: Option<FilterConfig>,
}

/// Available output formats
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OutputFormat {
    Pretty,
    Json,
    Sarif,
    Markdown,
    Html,
    Junit,
}

/// Grouping options for reports
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum GroupBy {
    Scanner,
    Severity,
    Category,
    File,
}

/// Sorting options for reports
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SortBy {
    Severity,
    Category,
    File,
    Time,
}

/// Filter configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct FilterConfig {
    pub severity: Option<Vec<Severity>>,
    pub category: Option<Vec<String>>,
    pub scanner: Option<Vec<String>>,
    pub file_pattern: Option<String>,
    pub min_severity: Option<Severity>,
    pub max_issues: Option<usize>,
}

/// Error types for report generation
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("Failed to format report: {0}")]
    FormatError(String),
    #[error("Invalid output format: {0}")]
    InvalidFormat(String),
    #[error("Failed to write report: {0}")]
    WriteError(String),
    #[error("Invalid filter configuration: {0}")]
    FilterError(String),
    #[error("Invalid grouping configuration: {0}")]
    GroupError(String),
    #[error("Invalid sorting configuration: {0}")]
    SortError(String),
}

/// A security issue found
#[derive(Debug, Serialize)]
pub struct Issue {
    pub id: String,
    pub category: String,
    pub severity: Severity,
    pub description: String,
    pub location: Location,
    pub fix: Option<String>,
    pub references: Vec<String>,
}

/// Location of an issue
#[derive(Debug, Serialize)]
pub struct Location {
    pub path: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

/// Severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Scan result from any scanner
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub scanner: String,
    pub target: String,
    pub issues: Vec<Issue>,
    pub metadata: HashMap<String, Value>,
    pub scan_time: String,
}

/// Generate a report from scan results
pub fn generate_report(
    results: &[ScanResult],
    config: &ReportConfig,
) -> Result<String> {
    match config.output_format {
        OutputFormat::Pretty => formats::pretty::generate(results, config),
        OutputFormat::Json => formats::json::generate(results, config),
        OutputFormat::Sarif => formats::sarif::generate(results, config),
    }
}

/// Generate statistics from scan results
pub fn generate_statistics(results: &[ScanResult]) -> Statistics {
    let mut stats = Statistics::new();
    
    for result in results {
        stats.total_scans += 1;
        stats.scanners.insert(result.scanner.clone(), 1);
        
        for issue in &result.issues {
            stats.total_issues += 1;
            stats.issues_by_severity.entry(issue.severity).or_insert(0) += 1;
            stats.issues_by_category.entry(issue.category.clone()).or_insert(0) += 1;
        }
    }
    
    stats
}

/// Report statistics
#[derive(Debug, Serialize)]
pub struct Statistics {
    pub total_scans: usize,
    pub total_issues: usize,
    pub scanners: HashMap<String, usize>,
    pub issues_by_severity: HashMap<Severity, usize>,
    pub issues_by_category: HashMap<String, usize>,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            total_scans: 0,
            total_issues: 0,
            scanners: HashMap::new(),
            issues_by_severity: HashMap::new(),
            issues_by_category: HashMap::new(),
        }
    }
}
