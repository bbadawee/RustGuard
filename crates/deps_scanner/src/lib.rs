use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub mod parsers;
pub mod osv;

/// Dependency scanning result
#[derive(Debug, Serialize)]
pub struct DepScanResult {
    pub package: String,
    pub version: String,
    pub vulnerabilities: Vec<Vulnerability>,
}

/// A vulnerability found in a dependency
#[derive(Debug, Serialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: Severity,
    pub description: String,
    pub fixed_in: Option<String>,
    pub references: Vec<String>,
}

/// Severity levels for vulnerabilities
#[derive(Debug, Serialize, Clone, Copy)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Configuration for dependency scanning
#[derive(Debug, Serialize)]
pub struct DepScannerConfig {
    pub osv_api_url: String,
    pub timeout: u64,
    pub cache_dir: Option<PathBuf>,
    pub ignore_dev_dependencies: bool,
    pub ignore_patterns: Vec<String>,
    pub max_concurrent_requests: usize,
    pub offline_mode: bool,
}

impl Default for DepScannerConfig {
    fn default() -> Self {
        Self {
            osv_api_url: "https://api.osv.dev/v1/query".to_string(),
            timeout: 10,
            cache_dir: Some(PathBuf::from(".rustguard_cache")),
            ignore_dev_dependencies: false,
            ignore_patterns: vec![],
            max_concurrent_requests: 5,
            offline_mode: false,
        }
    }
}

/// Error types for dependency scanning
#[derive(Debug, thiserror::Error)]
pub enum DepScanError {
    #[error("Failed to parse lockfile: {0}")]
    ParseError(String),
    #[error("Failed to fetch vulnerability data: {0}")]
    FetchError(String),
    #[error("Invalid package format: {0}")]
    InvalidPackage(String),
    #[error("Timeout while scanning dependencies")]
    Timeout,
    #[error("Cache error: {0}")]
    CacheError(String),
}

/// Parse a lockfile and return dependencies
pub async fn parse_lockfile(path: &Path) -> Result<Vec<Dependency>> {
    let extension = path.extension().and_then(|ext| ext.to_str());
    
    match extension {
        Some("Cargo.lock") => parsers::cargo::parse_cargo_lock(path).await,
        Some("package-lock.json") => parsers::npm::parse_package_lock(path).await,
        Some("requirements.txt") => parsers::pip::parse_requirements(path).await,
        Some("go.sum") => parsers::go::parse_go_sum(path).await,
        _ => Err(anyhow::anyhow!("Unsupported lockfile format")),
    }
}

/// Check dependencies against OSV for vulnerabilities
pub async fn check_vulnerabilities(
    dependencies: &[Dependency],
    config: &DepScannerConfig,
) -> Result<Vec<DepScanResult>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout))
        .build()?;
    
    let mut results = Vec::new();
    
    for dep in dependencies {
        let vulnerabilities = osv::check_dependency(&client, dep, config).await?;
        if !vulnerabilities.is_empty() {
            results.push(DepScanResult {
                package: dep.name.clone(),
                version: dep.version.clone(),
                vulnerabilities,
            });
        }
    }
    
    Ok(results)
}

/// Scan a directory for lockfiles and check dependencies
pub async fn scan_directory(
    path: &Path,
    config: &DepScannerConfig,
) -> Result<Vec<DepScanResult>> {
    let mut results = Vec::new();
    
    // Find all lockfiles in directory
    let paths = tokio::fs::read_dir(path).await?;
    
    for entry in paths {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() {
            match parse_lockfile(&path).await {
                Ok(deps) => {
                    let vulns = check_vulnerabilities(&deps, config).await?;
                    results.extend(vulns);
                }
                Err(e) => eprintln!("Failed to parse {}: {}", path.display(), e),
            }
        }
    }
    
    Ok(results)
}
