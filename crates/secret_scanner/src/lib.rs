use anyhow::Result;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub mod patterns;

/// Secret scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScannerConfig {
    pub entropy_threshold: f64,
    pub patterns: Vec<Pattern>,
}

impl Default for SecretScannerConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 4.5,
            patterns: patterns::DEFAULT_PATTERNS.to_vec(),
        }
    }
}

/// A pattern for detecting secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub name: String,
    pub regex: String,
    pub description: String,
    pub severity: Severity,
}

impl Pattern {
    pub fn new(name: &str, regex: &str, description: &str, severity: Severity) -> Self {
        Self {
            name: name.to_string(),
            regex: regex.to_string(),
            description: description.to_string(),
            severity,
        }
    }
}

/// Secret scanning result
#[derive(Debug, Serialize)]
pub struct SecretScanResult {
    pub path: PathBuf,
    pub line_number: usize,
    pub secret_type: String,
    pub secret: String,
    pub entropy: f64,
    pub pattern: Option<String>,
}

/// Calculate Shannon entropy of a string
fn calculate_entropy(s: &str) -> f64 {
    let mut entropy = 0.0;
    let mut counts = [0; 256];
    
    for byte in s.bytes() {
        counts[byte as usize] += 1;
    }
    
    let total = s.len() as f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    
    entropy
}

/// Scan a single file for secrets
pub async fn scan_file(path: &Path, config: &SecretScannerConfig) -> Result<Vec<SecretScanResult>> {
    let content = tokio::fs::read_to_string(path).await?;
    let lines: Vec<&str> = content.lines().collect();
    
    let mut results = Vec::new();
    
    // Check patterns
    for pattern in &config.patterns {
        let re = Regex::new(&pattern.regex)?;
        for (line_number, line) in lines.iter().enumerate() {
            if let Some(caps) = re.captures(line) {
                let secret = caps.get(0).unwrap().as_str().to_string();
                let entropy = calculate_entropy(&secret);
                
                if entropy > config.entropy_threshold {
                    results.push(SecretScanResult {
                        path: path.to_path_buf(),
                        line_number: line_number + 1,
                        secret_type: pattern.name.clone(),
                        secret,
                        entropy,
                        pattern: Some(pattern.name.clone()),
                    });
                }
            }
        }
    }
    
    // Check entropy for base64-like strings
    let base64_pattern = Regex::new(r"[A-Za-z0-9+/=]{20,}").unwrap();
    for (line_number, line) in lines.iter().enumerate() {
        if let Some(caps) = base64_pattern.captures(line) {
            let secret = caps.get(0).unwrap().as_str().to_string();
            let entropy = calculate_entropy(&secret);
            
            if entropy > config.entropy_threshold {
                results.push(SecretScanResult {
                    path: path.to_path_buf(),
                    line_number: line_number + 1,
                    secret_type: "Base64-like string".to_string(),
                    secret,
                    entropy,
                    pattern: None,
                });
            }
        }
    }
    
    Ok(results)
}

/// Scan a directory recursively for secrets
pub async fn scan_directory(
    path: &Path,
    config: &SecretScannerConfig,
) -> Result<Vec<SecretScanResult>> {
    let mut results = Vec::new();
    
    let paths = tokio::fs::read_dir(path).await?;
    let paths = paths.collect::<Vec<_>>();
    
    for entry in paths {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_dir() {
            results.extend(scan_directory(&path, config).await?);
        } else if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "git" || ext == "lock" || ext == "json" || ext == "yaml" || ext == "yml" {
                    results.extend(scan_file(&path, config).await?);
                }
            }
        }
    }
    
    Ok(results)
}
