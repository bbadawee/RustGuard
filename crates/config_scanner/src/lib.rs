use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub mod parsers;
pub mod rules;
pub mod profiles;

/// Configuration scanning result
#[derive(Debug, Serialize)]
pub struct ConfigScanResult {
    pub file: String,
    pub issues: Vec<Issue>,
    pub metadata: ConfigMetadata,
}

/// Configuration metadata
#[derive(Debug, Serialize)]
pub struct ConfigMetadata {
    pub file_type: String,
    pub size: u64,
    pub modified: String,
}

/// An issue found in a configuration file
#[derive(Debug, Serialize)]
pub struct Issue {
    pub id: String,
    pub rule: String,
    pub severity: Severity,
    pub description: String,
    pub location: Location,
    pub fix: Option<String>,
    pub references: Vec<String>,
}

/// Location of an issue in a configuration file
#[derive(Debug, Serialize)]
pub struct Location {
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub path: Option<String>,
}

/// Severity levels for issues
#[derive(Debug, Serialize, Clone, Copy)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Configuration for configuration scanning
#[derive(Debug, Serialize)]
pub struct ConfigScannerConfig {
    pub rules: Vec<Rule>,
    pub profiles: HashMap<String, Profile>,
    pub timeout: u64,
    pub ignore_patterns: Vec<String>,
    pub max_file_size: u64,
    pub check_syntax: bool,
    pub validate_schema: bool,
    pub schema_dir: Option<PathBuf>,
}

impl Default for ConfigScannerConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            profiles: HashMap::new(),
            timeout: 10,
            ignore_patterns: vec![],
            max_file_size: 1024 * 1024, // 1MB
            check_syntax: true,
            validate_schema: false,
            schema_dir: None,
        }
    }
}

/// Error types for configuration scanning
#[derive(Debug, thiserror::Error)]
pub enum ConfigScanError {
    #[error("Failed to parse configuration: {0}")]
    ParseError(String),
    #[error("Failed to validate schema: {0}")]
    SchemaError(String),
    #[error("File too large: {0} bytes")]
    FileTooLarge(u64),
    #[error("Pattern error: {0}")]
    PatternError(String),
    #[error("Rule error: {0}")]
    RuleError(String),
    #[error("Timeout while scanning configuration")]
    Timeout,
}

/// Scan a single configuration file
pub async fn scan_file(
    path: &Path,
    config: &ConfigScannerConfig,
) -> Result<ConfigScanResult> {
    let content = tokio::fs::read_to_string(path).await?;
    let file_type = parsers::detect_file_type(path).await?;
    
    let mut issues = Vec::new();
    
    // Apply relevant rules based on file type
    for rule in &config.rules {
        if rule.applies_to(&file_type) {
            let rule_issues = rule.check(&content, path).await?;
            issues.extend(rule_issues);
        }
    }
    
    // Check against profiles
    for (profile_name, profile) in &config.profiles {
        if profile.applies_to(&file_type) {
            let profile_issues = profile.check(&content, path).await?;
            issues.extend(profile_issues);
        }
    }
    
    Ok(ConfigScanResult {
        file: path.to_string_lossy().to_string(),
        issues,
        metadata: ConfigMetadata {
            file_type,
            size: content.len() as u64,
            modified: chrono::Local::now().to_rfc3339(),
        },
    })
}

/// Scan a directory for configuration files
pub async fn scan_directory(
    path: &Path,
    config: &ConfigScannerConfig,
) -> Result<Vec<ConfigScanResult>> {
    let mut results = Vec::new();
    
    // Find configuration files
    let paths = tokio::fs::read_dir(path).await?;
    
    for entry in paths {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() {
            // Check file extensions
            if let Some(ext) = path.extension() {
                if ext == "yaml" || ext == "yml" || ext == "json" || ext == "tf" {
                    match scan_file(&path, config).await {
                        Ok(result) => results.push(result),
                        Err(e) => eprintln!("Failed to scan {}: {}", path.display(), e),
                    }
                }
            }
        }
    }
    
    Ok(results)
}

/// Generate a compliance report for a set of configuration files
pub fn generate_compliance_report(
    results: &[ConfigScanResult],
    config: &ConfigScannerConfig,
) -> ComplianceReport {
    let mut report = ComplianceReport::new();
    
    for result in results {
        for issue in &result.issues {
            report.add_issue(issue);
        }
    }
    
    report
}
