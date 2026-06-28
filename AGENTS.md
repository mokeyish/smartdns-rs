# SmartDNS-rs Development Guide

## Project Overview

**SmartDNS-rs** is a high-performance local DNS server written in Rust, inspired by [C SmartDNS](https://github.com/pymumu/smartdns). It accepts DNS query requests from local clients, obtains DNS query results from multiple upstream DNS servers, and returns the fastest access results to clients.

### Key Features
- **Multiple upstream DNS servers** - Query from multiple DNS servers simultaneously
- **Fastest IP selection** - Returns the fastest accessible IP address to avoid DNS pollution
- **Multiple query protocols** - Supports UDP, TCP, DoT, DoQ, DoH, DoH3
- **Domain IP specification** - Ad filtering and malicious website prevention
- **DNS forwarding** - Supports ipset and nftables
- **Multi-platform** - Windows, macOS, Linux support
- **IPv4/IPv6 dual-stack** - Full IPv6 support with DNS64 translation
- **High performance** - Tokio-based async I/O with caching

---

## Architecture

### Directory Structure

```
smartdns-rs/
├── src/
│   ├── main.rs                 # Application entry point
│   ├── app.rs                  # Main application logic
│   ├── cli.rs                  # CLI argument parsing
│   ├── dns.rs                  # DNS data structures
│   ├── dns_client.rs           # DNS client & upstream servers
│   ├── dns_conf.rs             # Configuration loading & runtime config
│   ├── dns_error.rs            # Error types
│   ├── dns_mw.rs               # Middleware trait
│   ├── dns_mw_*.rs             # Middleware implementations:
│   │   ├── dns_mw_addr.rs      # Address/domain rules
│   │   ├── dns_mw_audit.rs     # Query auditing
│   │   ├── dns_mw_bogus.rs     # Bogus check
│   │   ├── dns_mw_cache.rs     # Query caching
│   │   ├── dns_mw_cname.rs     # CNAME handling
│   │   ├── dns_mw_dns64.rs     # DNS64 translation
│   │   ├── dns_mw_dnsmasq.rs   # dnsmasq lease file support (PTR lookup)
│   │   ├── dns_mw_dualstack.rs # Dual-stack IP selection
│   │   ├── dns_mw_hosts.rs     # Hosts file support
│   │   ├── dns_mw_nftset.rs    # nftables support (Linux)
│   │   ├── dns_mw_ns.rs        # Nameserver rules
│   │   └── dns_mw_zone.rs      # Zone file support
│   ├── dns_rule.rs             # Domain matching rules
│   ├── dns_url.rs              # DNS URL parsing
│   ├── dnsmasq.rs              # dnsmasq lease file parsing
│   ├── collections.rs          # Custom collections (DomainMap)
│   ├── infra/                  # Infrastructure utilities
│   │   ├── ping.rs             # ICMP ping
│   │   └── middleware.rs       # HTTP middleware
│   ├── libdns/                 # LibDNS compatibility layer
│   ├── log.rs                  # Logging setup
│   ├── preset_ns.rs            # Predefined nameservers
│   ├── proxy.rs                # HTTP/SOCKS5 proxy support
│   ├── rustls.rs               # TLS/SSL support
│   ├── resolver.rs             # DNS resolution
│   ├── server/                 # DNS server implementation
│   ├── third_ext/              # Third-party extensions
│   └── zone/                   # Zone data structures
├── config/                     # Configuration modules
├── etc/smartdns/              # Example configurations
├── tests/                     # Integration tests
├── Cargo.toml                 # Project dependencies
└── README.md                  # Project documentation
```

### Core Middleware Chain

DNS requests pass through a chain of middleware:

```
Request → [dnsmasq] → [hosts] → [cache] → [zone] → [audit] → [addr] → [dns64] → [dualstack] → [cname] → [nftset] → Upstream DNS
```

**dnsmasq middleware** (`dns_mw_dnsmasq.rs`):
- Handles PTR (reverse lookup) queries
- Checks LAN client lease files for IP→domain mapping
- Example: `192.168.1.100.in-addr.arpa.` → `Andy-PC`

**hosts middleware** (`dns_mw_hosts.rs`):
- Checks local `/etc/hosts` or custom hosts file
- Returns pre-defined domain→IP mappings

**cache middleware** (`dns_mw_cache.rs`):
- Caches query results
- Reduces upstream DNS queries
- Configurable TTL per domain

**dualstack middleware** (`dns_mw_dualstack.rs`):
- Selects fastest IP from multiple A/AAAA records
- Pings each IP to measure latency
- Returns best performing address

---

## Development Environment

### Prerequisites
- **Rust**: 1.70+ (stable recommended)
- **Cargo**: Included with Rust
- **OS**: Windows, macOS, Linux

### Setup

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone repository
git clone https://github.com/mokeyish/smartdns-rs.git
cd smartdns-rs

# Build
just build

# Run tests
just test
```

### Feature Flags

```toml
[features]
default = []
service = ["windows-service", "service"]          # Service installation
self-update = ["self_update"]                     # Self-update capability
nft = []                                           # nftables support (Linux)
resolve-cli = ["hickory-resolver"]                # CLI resolver tool
mdns = ["hickory-mdns"]                           # mDNS support
```

Common build commands:
```bash
# Build with all optional features
just build --release --features "service,nft,resolve-cli"

# Build for different targets
just build --release --target x86_64-unknown-linux-musl
just build --release --target aarch64-apple-darwin
```

---

## Configuration

### Configuration File Format

SmartDNS supports:
- **Conf format** (traditional) - `smartdns.conf`
- **JSON format** - `config.json`
- **YAML format** - `config.yaml`

### Example Configuration (smartdns.conf)

```conf
# Listen address
bind-address 0.0.0.0

# Upstream DNS servers
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 101.226.4.6

# Domain-specific DNS servers
nameserver-domain google.com 8.8.8.8
nameserver-domain baidu.com 101.226.4.6

# Address rules (ad filtering)
address-rule 1.1.1.1
address-rule 192.168.1.1

# Client rules
client-rule --client-ip 192.168.1.0/24 nameserver 1.1.1.1

# Domain blacklist
blacklist-ip google.com
blacklist-ip facebook.com

# Local files
hosts-file /etc/hosts
dnsmasq-lease-file /var/lib/misc/dnsmasq.leases
```

### Loading Configuration

```rust
// src/dns_conf.rs

let cfg = RuntimeConfig::load(directory, conf_file);

// Access configuration
let servers = cfg.servers();          // Upstream DNS servers
let cache_size = cfg.cache_size();    // Cache size
let hosts_file = cfg.hosts_file();    // Hosts file path
```

---

## Key Development Patterns

### Implementing Middleware

```rust
use crate::dns::*;
use crate::middleware::*;

pub struct MyMiddleware;

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> 
    for MyMiddleware 
{
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        // Handle request or pass to next middleware
        if should_handle(req) {
            let response = self.process(req);
            Ok(response)
        } else {
            next.run(ctx, req).await
        }
    }
}
```

### PTR Query Handling (Reverse Lookup)

**dns_mw_dnsmasq.rs**:
```rust
if req.query().query_type() == RecordType::PTR {
    // Convert PTR name to IP
    if let Ok(ip_addr) = Self::ptr_to_ip(req.query().name()) {
        // Look up in dnsmasq lease file
        if let Some(rdata) = self.client_store.reverse_lookup(&ip_addr) {
            let response = build_ptr_response(query, rdata);
            return Ok(response);
        }
    }
}
```

**ptr_to_ip() implementation**:
- IPv4: Parse `x.x.x.x.in-addr.arpa.`
- IPv6: Parse `x.x.x.x...ip6.arpa.` (reversed hex digits)

### DNS Client with Multiple Upstreams

**dns_client.rs**:
```rust
let mut builder = DnsClient::builder();
builder = builder.add_servers(vec![
    NameServerInfo::from("1.1.1.1"),
    NameServerInfo::from("8.8.8.8"),
]);

let client = builder.build().await;

// Query with concurrent upstreams
let results = client.lookup("google.com", RecordType::A, timeout).await;

// Select fastest response
let fastest = results.into_iter()
    .filter_map(|r| r.ok())
    .min_by_key(|r| r.query_time);
```

### IPv6 PTR Conversion

**dns_mw_dnsmasq.rs**:
```rust
pub fn ptr_to_ip(name: &Name) -> Result<IpAddr, AddrParseError> {
    let name_str = name.to_string();
    
    // IPv4 PTR
    if name_str.ends_with(".in-addr.arpa.") {
        let octets: Vec<&str> = name_str[..name_str.len() - ".in-addr.arpa.".len()]
            .split('.')
            .rev()
            .collect();
        // ... convert to IPv4
    }
    
    // IPv6 PTR
    else if name_str.ends_with(".ip6.arpa.") {
        let hex_digits: String = name_str[..name_str.len() - ".ip6.arpa.".len()]
            .chars()
            .filter(|c| *c != '.')
            .collect();
        
        if hex_digits.len() == 32 {
            // Reverse and format as IPv6
            let reversed: String = hex_digits.chars().rev().collect();
            let ipv6_str = format!(
                "{}:{}:{}:{}:{}:{}:{}:{}",
                &reversed[0..4], &reversed[4..8], &reversed[8..12],
                &reversed[12..16], &reversed[16..20], &reversed[20..24],
                &reversed[24..28], &reversed[28..32]
            );
            return Ok(ipv6_str.parse::<Ipv6Addr>()?.into());
        }
    }
    
    Err("invalid".parse().unwrap_err())
}
```

---

## Testing

### Using Just Commands

The project uses `just` as a build tool for convenient commands:

```bash
# Run all tests
just test

# Run specific test
just test test_ptr_to_ip_ipv6
just test dns_mw_dnsmasq

# Run tests with filter
just test PTR
```

### Test Organization

**Important**: Unit tests must be placed at the end of the file, after all public code.

**Correct order**:
```rust
// 1. Imports
use crate::dns::*;

// 2. Public structs and impls
pub struct MyStruct;

impl MyStruct {
    // ... implementation
}

// 3. Tests (at the end)
#[cfg(test)]
mod tests {
    // ... tests
}
```

**Example** (`dns_mw_dnsmasq.rs`):
```rust
use crate::dns::*;

pub struct DnsmasqMiddleware { ... }

impl DnsmasqMiddleware {
    pub fn ptr_to_ip(...) { ... }
}

// Tests at the end
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ptr_to_ip_ipv4() { ... }
}
```

### Using cargo directly (not recommended)

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Test coverage
cargo tarpaulin --out Html
```

### Test Coverage

- **Unit tests**: Each module has inline `#[cfg(test)]` modules
- **Integration tests**: Located in `tests/` directory
- **Sample data**: `tests/test_data/` contains sample lease files, hosts files, zone files

### PTR Test Examples

```rust
#[test]
fn test_ptr_to_ip_ipv4() {
    let name = Name::from_str("16.100.168.192.in-addr.arpa.").unwrap();
    let ip = DnsmasqMiddleware::ptr_to_ip(&name).unwrap();
    assert_eq!(ip, IpAddr::from_str("192.168.100.16").unwrap());
}

#[test]
fn test_ptr_to_ip_ipv6() {
    let name = Name::from_str("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.").unwrap();
    let ip = DnsmasqMiddleware::ptr_to_ip(&name).unwrap();
    assert_eq!(ip, IpAddr::from_str("::1").unwrap());
    
    let name = Name::from_str("7.4.9.4.8.1.0.f.1.7.6.9.0.0.0.0.0.0.5.e.3.1.0.1.0.0.e.4.2.0.4.2.ip6.arpa.").unwrap();
    let ip = DnsmasqMiddleware::ptr_to_ip(&name).unwrap();
    assert_eq!(ip, IpAddr::from_str("2402:4e00:1013:e500:0:9671:f018:4947").unwrap());
}

#[test]
fn test_dnsmasq_middleware_reverse_lookup() {
    let mw = DnsmasqMiddleware::new("tests/test_data/dhcp.leases", None);
    let _ = mw.client_store.lookup(&"Andy-PC".parse().unwrap(), RecordType::A);
    
    let name = Name::from_str("16.100.168.192.in-addr.arpa.").unwrap();
    let ip = DnsmasqMiddleware::ptr_to_ip(&name).unwrap();
    let rdata = mw.client_store.reverse_lookup(&ip);
    assert!(rdata.is_some());
}
```

---

## Code Quality

### Using Just for Code Quality

```bash
# Format all code
just fmt

# Check code quality (clippy + format)
just cleanliness

# Fix clippy warnings
just clippy
```

### Using cargo directly (not recommended)

```bash
# Format code
cargo fmt --all

# Check format without modifying
cargo fmt --all --check

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
```

1. Create `src/dns_mw_new.rs`
2. Implement middleware trait:
```rust
#[async_trait::async_trait]
impl Middleware<...> for NewMiddleware {
    async fn handle(...) -> Result<DnsResponse, DnsError> { ... }
}
```
3. Export in `src/dns_mw.rs`:
```rust
pub mod dns_mw_new;
pub use dns_mw_new::*;
```
4. Add to middleware chain in `app.rs`

### Debugging DNS Queries

```rust
// Enable debug logging
export RUST_LOG=debug
just run -- run --conf smartdns.conf

// Or in code
log::set_max_level(log::LevelFilter::Debug);
```

### Performance Profiling

```bash
# Build with profiling symbols
cargo build --release --profile perf

# Run with flamegraph
just run --profile perf -- --conf smartdns.conf
```

### Building for Production

```bash
# Linux static binary
just build --release --target x86_64-unknown-linux-musl

# macOS
just build --release --target aarch64-apple-darwin

# Windows
just build --release --target x86_64-pc-windows-msvc

# Docker
cd docker && docker build -t smartdns .
```

---

## Troubleshooting

### Common Issues

1. **Permission denied on port 53**
   ```bash
   just run -- run --conf smartdns.conf
   # Or use non-privileged port
   bind-address 127.0.0.1:5053
   ```

2. **PTR lookup not working**
   - Verify dnsmasq lease file exists and is readable
   - Check lease file format matches dnsmasq output
   - Test with: `just test dns_mw_dnsmasq`

3. **IPv6 PTR conversion fails**
   - Ensure PTR name has 32 hex characters
   - Verify hex digits are in correct (reversed) order
   - Check test: `test_ptr_to_ip_ipv6`

4. **Service won't start**
   ```bash
   # Check logs
   journalctl -u smartdns -f  # Linux systemd
   # Or run manually for verbose output
   just run -- run --conf smartdns.conf
   ```

---

## References

- [Official Documentation](https://pymumu.github.io/smartdns/en/)
- [C SmartDNS](https://github.com/pymumu/smartdns)
- [Rust Tokio](https://tokio.rs/)
- [Hickory DNS](https://github.com/hickory-dns/hickory-dns/) (formerly trust-dns, re-exported via libdns.rs)
- [Cargo Book](https://doc.rust-lang.org/cargo/)

### Dependencies History

Hickory DNS was previously known as `trust-dns`. To avoid breaking changes during the rename, the project uses `libdns.rs` as an abstraction layer and re-exports the necessary functionality. This allows the codebase to remain compatible with both old and new versions of the DNS resolver.

---

## Code Principles

Writing maintainable, high-quality code is essential for long-term project success. Follow these principles when contributing:

### 1. **Minimal Changes**
- Modify only what's necessary to fix a bug or add a feature
- Avoid over-engineering
- If a simple fix works, don't add complexity

```rust
// ❌ Over-engineered
pub fn process_data(data: &mut Vec<String>) {
    let temp: Vec<String> = data.drain(..).collect();
    // ... complex transformation ...
}

// ✅ Minimal
pub fn process_item(item: &str) -> Option<String> {
    // Simple, focused logic
}
```

### 2. **Clarity Over Cleverness**
- Code is read more often than written
- Avoid "too clever" one-liners
- Choose explicit over implicit

```rust
// ❌ Clever but unclear
let result = data.iter().filter(|x| x.0 > 0).map(|x| x.1 * 2).collect::<Vec<_>>();

// ✅ Clear and readable
let positive_values: Vec<i32> = data.iter()
    .filter(|&(value, _)| value > 0)
    .map(|&(_, multiplier)| multiplier * 2)
    .collect();
```

### 3. **Fail Fast**
- Validate inputs early (like `ClientInfo::from_str`)
- Don't defer checks to later stages
- Clear error messages

```rust
// ✅ Validate during creation
let host = match parts.next().map(Name::from_str) {
    Some(Ok(v)) => {
        let hostname_str = v.to_string();
        if hostname_str.is_empty() {
            return Err(());  // Fail immediately
        }
        v
    }
    _ => return Err(()),
};
```

### 4. **Single Responsibility**
- Each function does one thing
- Each module has a clear purpose
- Don't mix concerns

```rust
// ❌ Mixed concerns
pub fn handle_query(query: &Query) -> Result<Response, Error> {
    // Parse config, validate input, query DNS, cache result, log...
}

// ✅ Separate concerns
pub fn parse_config(path: &Path) -> Result<Config, Error>;
pub fn validate_query(query: &Query) -> Result<(), Error>;
pub fn query_dns(client: &Client, query: &Query) -> Result<Response, Error>;
```

### 5. **Tests at File End**
- Unit tests must be at the end of the file
- After all public code (structs, impls)
- Documented in AGENTS.md

**Test Distribution:**
- `src/dnsmasq.rs` - Low-level tests (ClientInfo, LanClientStore, ptr_to_ip, reverse_lookup)
- `src/dns_mw_dnsmasq.rs` - Integration tests (middleware chain)

**Test Quality:**
- Verify `Option` contains correct values, not just `Some`
- Check actual content matches expected data
- Test both success and error paths

```rust
// ✅ Good test - verifies content
if let Some(RData::PTR(ptr)) = rdata {
    assert_eq!(ptr.0.to_string(), "andy-pc.", "Hostname should match");
}

// ❌ Bad test - only checks Some/None
assert!(rdata.is_some());
```

```rust
// Correct order:
// 1. Imports
use crate::dns::*;

// 2. Public code
pub struct MyStruct;

impl MyStruct { ... }

// 3. Tests (at the end)
#[cfg(test)]
mod tests { ... }
```

### 6. **Defensive Programming**
- Validate inputs
- Check edge cases
- Handle errors gracefully

```rust
pub fn reverse_lookup(&self, ip: &IpAddr) -> Option<RData> {
    if let Some(client_info) = lease_cache.ip_clients.get(ip) {
        // Skip placeholder hostnames like "*"
        if client_info.host.to_string() != "*" {
            return Some(RData::PTR(PTR(client_info.host.clone())));
        }
    }
    None  // Explicitly return None for invalid cases
}
```

### 7. **KISS (Keep It Simple, Stupid)**
- Prefer simple solutions over complex ones
- Don't add features that aren't needed
- If it's complex, ask why

### 8. **Consistency**
- Follow existing patterns in the codebase
- Use consistent naming conventions
- Error handling should follow the same pattern

### 9. **Documentation as Code**
- Add doc comments to public APIs
- Explain "why" not just "what"
- Keep docs updated with changes

### 10. **Type Safety**
- Use Rust's type system to express constraints
- Avoid `Option<Option<T>>` - prefer `Result`
- Let the compiler catch errors early

### 11. **Defensive Testing**
- Test boundary conditions
- Test error paths
- Tests should document expected behavior

### 12. **Performance Awareness**
- Don't optimize prematurely
- Profile before optimizing
- Critical paths can be optimized later

### 13. **Third-Party Library Guidelines**
- **Always check local source code first** before searching online
- Search path: `$HOME/.cargo/git/checkouts/<crate>/<rev>/` or `$HOME/.cargo/registry/src/`
- GitHub links may become outdated or 404
- Example search commands:
  ```bash
  # Find local source
  find $HOME/.cargo -name "*.rs" | grep -E "(name\.rs|arpa\.rs)" | head -5
  
  # View specific file
  cat $HOME/.cargo/git/checkouts/hickory-dns-*/crates/proto/src/rr/domain/name.rs | grep -A10 "parse_arpa_name"
  
  # Search for function
  grep -r "parse_arpa_name" $HOME/.cargo/git/checkouts/hickory-dns*/ 2>/dev/null | head -3
  ```

- When refactoring to use built-in APIs (e.g., `Name::parse_arpa_name()`), always verify the local implementation first
- Library versions are pinned in `Cargo.toml` - check exact commit/rev for accurate reference

---

## Git & Contribution Guidelines

### Commit Message Format

We follow the **Conventional Commits** specification. Commit messages should follow this format:

```text
<type>(<scope>): <subject>

<body>
```

#### Commit Type Categories

| Type | Meaning | When to Use |
| :--- | :--- | :--- |
| **feat** | New Feature | Introduces a new feature or functionality |
| **fix** | Bug Fix | Fixes a bug or vulnerability in the code |
| **docs** | Documentation | Only modifies documentation, README, or comments |
| **style** | Code Style | Changes that don't affect code meaning (formatting, whitespace, missing semicolons) |
| **refactor** | Refactoring | Large or medium refactoring of logic structure or core modules |
| **tweak** | Tweaks | Local code adjustments, minor optimizations, or renaming |
| **perf** | Performance | Improves performance, load speed, or reduces memory usage |
| **test** | Tests | Adds, modifies, or removes test code |
| **chore** | Build/Tools | Modifies build tools, dependencies, or utility tools |
| **ci** | CI Configuration | Modifies CI scripts or config files |
| **revert** | Revert | Reverts a previous commit |

**Examples:**
- `refactor(auth): rewrite the token validation module`
- `tweak(auth): optimize variable naming in login component`
- `feat(dns): add IPv6 PTR lookup support`
- `fix(cache): resolve cache invalidation issue`

⚠️ **Breaking Changes**: Add `!` after the type (e.g., `feat!: remove deprecated API`) or note in the footer.

### Branch Management

* Main branch: `main` (stable releases only)
* **Never commit directly to `main`**
* Create feature branches from `main`:
  * Features: `feat/your-feature-name`
  * Bug fixes: `fix/your-bug-name`
  * Documentation: `docs/your-docs-name`

```bash
git checkout main
git pull origin main
git checkout -b feat/my-new-feature
```

### PR/MR Workflow

1. **Squash intermediate commits** before submitting:
   ```bash
   git rebase -i HEAD~3  # Change 'pick' to 'squash' for older commits
   ```

2. **Rebase on latest main** to avoid merge commits:
   ```bash
   git checkout main
   git pull origin main
   git checkout your-branch
   git rebase main
   ```

3. **Force push** after rebasing:
   ```bash
   git push origin your-branch --force
   ```

4. **Create PR/MR** with clear description, referencing related issues with `Closes #123`

### Pre-Submission Checklist

Before submitting a PR/MR:
* [ ] All tests pass: `just test`
* [ ] Code is formatted: `just fmt`
* [ ] No clippy warnings: `just clippy`
* [ ] Commit messages follow Conventional Commits
* [ ] Unit tests added for new features
* [ ] Unit tests placed at end of file (after all public code)
* [ ] Tests verify actual content, not just `Some`/`None`

---

## Agent Guidelines

### ⚠️ IMPORTANT: Git Commit Policy

**Do NOT submit commits to the repository without explicit user review and approval.**

When making changes:
1. Always **stage changes first** using `git add <files>`
2. **DO NOT** run `git commit` without explicit user instruction
3. Show the user what you've staged with `git diff --staged`
4. Wait for user confirmation before committing
5. Let the user review:
   - Which files are modified
   - What changes were made
   - Whether the commit message is appropriate

This policy ensures:
- User maintains control over what gets committed
- No unintended files or changes are committed
- User can review commit messages and descriptions
- Avoids accidental commits to wrong branches

**Exception**: You may commit changes if explicitly instructed by the user after they've reviewed the staged changes.

