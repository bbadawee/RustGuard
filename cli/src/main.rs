use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rustguard_config::{CliArgs, RuntimeConfig};
use rustguard_scanner_core::ScannerContext;

#[tokio::main]
async fn main() -> Result<()> {
    let cli_args = CliArgs::parse();
    let config = RuntimeConfig::from(cli_args);
    
    // Initialize scanner context
    let scanner = ScannerContext::new(config.clone());
    
    // Create progress bar
    let pb = ProgressBar::new(100);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos:>7}/{len:7} ({eta})")
        .unwrap()
        .progress_chars("#>-"));
    
    // Start scanning
    println!("{} Starting scan...", "[INFO]".blue());
    pb.set_message("Scanning target");
    
    let results = scanner.scan(config.target_path.to_str().unwrap_or("."))
        .await
        .unwrap_or_else(|e| {
            eprintln!("{} Failed to scan: {}", "[ERROR]".red(), e);
            std::process::exit(1);
        });
    
    // Format and display results
    match config.output_format {
        rustguard_config::OutputFormat::Pretty => {
            println!("\n{} Scan Results:", "[RESULTS]".green());
            for result in results {
                println!("\nTarget: {}", result.target);
                println!("Scan Time: {}ms", result.scan_time.as_millis());
                println!("Issues Found: {}", result.issues.len());
                
                if !result.issues.is_empty() {
                    println!("\nIssues:");
                    for issue in result.issues {
                        let severity_color = match issue.severity {
                            rustguard_scanner_core::Severity::Critical => "red",
                            rustguard_scanner_core::Severity::High => "yellow",
                            rustguard_scanner_core::Severity::Medium => "cyan",
                            rustguard_scanner_core::Severity::Low => "blue",
                            rustguard_scanner_core::Severity::Info => "green",
                        };
                        
                        println!(
                            "- [{}] {}{}{}{}",
                            format!("{:?}", issue.severity).to_uppercase().color(severity_color),
                            issue.description,
                            if let Some(loc) = &issue.location {
                                format!(" (Location: {})", loc)
                            } else { String::new() }
                            },
                            if let Some(fix) = &issue.fix {
                                format!("\n  Fix: {}", fix)
                            } else { String::new() }
                            },
                        );
                    }
                }
            }
        }
        rustguard_config::OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&results).unwrap());
        }
        rustguard_config::OutputFormat::Sarif => {
            // TODO: Implement SARIF output
            println!("SARIF output format not yet implemented");
        }
    }
    
    Ok(())
}
