# RustGuard

[![GitHub stars](https://img.shields.io/github/stars/bzhar/RustGuard.svg?style=social)](https://github.com/bzhar/RustGuard/stargazers)
[![GitHub license](https://img.shields.io/github/license/bzhar/RustGuard.svg)](https://github.com/bzhar/RustGuard/blob/master/LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.60+-blue.svg)](https://www.rust-lang.org)


A unified, fast, and secure security scanning tool built in Rust. RustGuard helps developers detect security vulnerabilities, secrets, and configuration issues in their codebase, dependencies, and containers.

## 🚀 Features

- 🔒 **Secret Detection**: Scan for hardcoded secrets, API keys, and sensitive data
- 📦 **Dependency Analysis**: Identify vulnerable dependencies across multiple package managers
- 🐳 **Container Security**: Analyze Docker/OCI images for security issues
- 📋 **Configuration Compliance**: Validate infrastructure-as-code and configuration files
- 📊 **Multi-format Reports**: Generate reports in JSON, SARIF, Markdown, and more
- ⚡ **High Performance**: Built in Rust for speed and efficiency
- 🎯 **Extensible**: Designed for custom plugins and integrations
- 🤖 **CI/CD Ready**: Perfect for automated security scanning

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/bzhar/RustGuard.git
cd RustGuard

# Build and install
cargo install --path .
```

### Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/bzhar/RustGuard/releases) page.

## 🛠️ Usage

```bash
# Basic scan
rustguard scan ./path/to/project

# Scan specific components
rustguard scan-secrets ./path/to/project
rustguard scan-deps ./path/to/project
rustguard scan-image ./path/to/image
rustguard scan-config ./path/to/config

# Advanced options
rustguard scan --output json --severity critical,high --ignore-pattern "*.test"
```

## 📚 Configuration

Create a `rustguard.toml` configuration file:

```toml
[scan]
output = "pretty"
severity = ["critical", "high"]

[deps]
ignore-dev-dependencies = true
max-concurrent-requests = 5

[secrets]
entropy-threshold = 4.5
ignore-patterns = ["*.test", "*.example"]

[container]
security-context = { privileged = false }
max-layers = 10
```

## 📊 Scan Types

### Secret Detection
- AWS Access Keys
- GitHub Tokens
- Stripe API Keys
- Firebase Secrets
- Azure AD Credentials
- And many more...

### Dependency Analysis
- Rust Cargo.lock
- Node.js package-lock.json
- Python requirements.txt
- Go mod
- And other package managers

### Container Security
- Layer analysis
- Package vulnerability scanning
- Security context validation
- CVE detection

### Configuration Compliance
- YAML/JSON validation
- Terraform security checks
- Kubernetes config analysis
- Infrastructure-as-code scanning

## 📝 Output Formats

- Pretty (terminal)
- JSON
- SARIF
- Markdown
- HTML
- JUnit

## 🛡️ Security

RustGuard is designed with security in mind:
- No network access required (offline mode)
- Secure secret detection algorithms
- CVE database caching
- Memory-safe Rust implementation
- Regular security updates

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to the Rust community for their amazing ecosystem
- Special thanks to contributors who have helped improve RustGuard
- Inspired by other security scanning tools while aiming to be better

## 📞 Support

- Report bugs on [GitHub Issues](https://github.com/bzhar/RustGuard/issues)
- Follow me on [Instagram](https://instagram.com/bbadawee)
