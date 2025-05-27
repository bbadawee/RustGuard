use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub mod image;
pub mod package;

/// Container scanning configuration
#[derive(Debug, Serialize)]
pub struct ContainerScannerConfig {
    pub timeout: u64,
    pub max_layers: usize,
    pub skip_layers: Vec<usize>,
    pub cache_dir: Option<PathBuf>,
    pub offline_mode: bool,
    pub ignore_patterns: Vec<String>,
    pub security_context: SecurityContext,
}

impl Default for ContainerScannerConfig {
    fn default() -> Self {
        Self {
            timeout: 30,
            max_layers: 100,
            skip_layers: Vec::new(),
            cache_dir: Some(PathBuf::from(".rustguard_cache")),
            offline_mode: false,
            ignore_patterns: vec![],
            security_context: SecurityContext::default(),
        }
    }
}

/// Security context for container scanning
#[derive(Debug, Default, Serialize)]
pub struct SecurityContext {
    pub privileged: bool,
    pub capabilities: Vec<String>,
    pub security_opt: Vec<String>,
    pub user: Option<String>,
    pub group: Option<String>,
}

/// Error types for container scanning
#[derive(Debug, thiserror::Error)]
pub enum ContainerScanError {
    #[error("Failed to pull image: {0}")]
    PullError(String),
    #[error("Failed to extract layer: {0}")]
    LayerError(String),
    #[error("Failed to check vulnerabilities: {0}")]
    VulnerabilityError(String),
    #[error("Cache error: {0}")]
    CacheError(String),
    #[error("Timeout while scanning container")]
    Timeout,
    #[error("Invalid image format: {0}")]
    InvalidImage(String),
}

/// Container scanning result
#[derive(Debug, Serialize)]
pub struct ContainerScanResult {
    pub image: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub layers: Vec<Layer>,
    pub metadata: ContainerMetadata,
}

/// A layer in a container image
#[derive(Debug, Serialize)]
pub struct Layer {
    pub id: String,
    pub size: u64,
    pub vulnerabilities: Vec<Vulnerability>,
}

/// Container metadata
#[derive(Debug, Serialize)]
pub struct ContainerMetadata {
    pub created: String,
    pub architecture: String,
    pub os: String,
    pub size: u64,
}

/// A vulnerability found in a container
#[derive(Debug, Serialize)]
pub struct Vulnerability {
    pub id: String,
    pub package: String,
    pub version: String,
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

/// Scan a container image
pub async fn scan_image(
    image: &str,
    config: &ContainerScannerConfig,
) -> Result<ContainerScanResult> {
    let mut image = image::Image::new(image).await?;
    
    // Pull image if needed
    image.pull().await?;
    
    // Get metadata
    let metadata = image.get_metadata().await?;
    
    // Get layers
    let layers = image.get_layers(config.max_layers).await?;
    
    // Scan each layer for vulnerabilities
    let mut vulnerabilities = Vec::new();
    let mut layer_results = Vec::new();
    
    for (i, layer) in layers.iter().enumerate() {
        if config.skip_layers.contains(&i) {
            continue;
        }
        
        let packages = package::extract_packages(&layer).await?;
        let layer_vulns = package::check_vulnerabilities(&packages).await?;
        
        vulnerabilities.extend(layer_vulns.iter().cloned());
        layer_results.push(Layer {
            id: layer.id.clone(),
            size: layer.size,
            vulnerabilities: layer_vulns,
        });
    }
    
    Ok(ContainerScanResult {
        image: image.name.clone(),
        vulnerabilities,
        layers: layer_results,
        metadata,
    })
}

/// Scan a Dockerfile
pub async fn scan_dockerfile(
    path: &Path,
    config: &ContainerScannerConfig,
) -> Result<Vec<ContainerScanResult>> {
    let content = tokio::fs::read_to_string(path).await?;
    let mut results = Vec::new();
    
    // Parse FROM instructions
    let from_pattern = regex::Regex::new(r"FROM\s+([\w-]+:[\w.-]+)").unwrap();
    for cap in from_pattern.captures_iter(&content) {
        if let Some(image) = cap.get(1) {
            let result = scan_image(image.as_str(), config).await?;
            results.push(result);
        }
    }
    
    Ok(results)
}

/// Scan a directory for Dockerfiles and container images
pub async fn scan_directory(
    path: &Path,
    config: &ContainerScannerConfig,
) -> Result<Vec<ContainerScanResult>> {
    let mut results = Vec::new();
    
    // Find Dockerfiles
    let paths = tokio::fs::read_dir(path).await?;
    
    for entry in paths {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() {
            if path.extension().and_then(|ext| ext.to_str()) == Some("Dockerfile") {
                let dockerfile_results = scan_dockerfile(&path, config).await?;
                results.extend(dockerfile_results);
            }
        }
    }
    
    Ok(results)
}
