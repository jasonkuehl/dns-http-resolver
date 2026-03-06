# DNS Resolver

[![Docker Build](https://github.com/yourusername/dns-http-resolver/actions/workflows/docker-build.yml/badge.svg)](https://github.com/yourusername/dns-http-resolver/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A DNS resolver tool with a web UI and JSON API that queries multiple DNS servers, detects differences, and highlights discrepancies.

## ✨ Features

### Core DNS Tools
- 🔍 **Multi-Server Lookup** - Query DNS records across 8+ public DNS providers simultaneously
- 🔄 **Record Type Support** - A, AAAA, MX, NS, CNAME, TXT, SOA, PTR, SRV, CAA, DNSKEY
- 📊 **Diff Highlighting** - Automatically detect and highlight differences between servers
- 🧭 **DNS Trace** - Visualize resolution path from root servers to authoritative nameservers
- 🛡️ **DNSSEC Validation** - See DNSSEC status (validated/unverified/failed) for all queries
- ⚡ **Parallel Queries** - Fast results with concurrent DNS requests
- 🔄 **Reverse Lookup** - Convert IP addresses to hostnames (PTR records)

### Advanced Security & Analysis
- 📧 **Email Security Analyzer** - Check SPF, DKIM, and DMARC records with scoring
- 🌍 **DNS Propagation Checker** - Check propagation across 16+ global DNS servers
- 🚫 **Blacklist Checker** - Check if IPs are listed on 12+ DNS blacklists (RBLs)
- 🔒 **Security Audit** - Comprehensive DNS security audit with grading
- 🔎 **Subdomain Scanner** - Discover 130+ common subdomains via DNS enumeration
- ⚖️ **DNS Diff** - Compare DNS records between domains or across servers
- 📋 **Zone Info** - Complete DNS record overview with service detection

### Platform Features
- 📱 **Responsive UI** - Works on desktop and mobile devices
- 🐳 **Docker Ready** - Easy deployment with Docker and Docker Compose
- 🔒 **Rate Limited** - Built-in protection against abuse

---

## 🚀 Getting Started

### Quick Start (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/dns-http-resolver.git
cd dns-http-resolver

# Run with the included script
./run.sh
```

Open http://localhost:60200 in your browser.

### Manual Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run with gunicorn
gunicorn --bind 0.0.0.0:60200 app:app

# Or run in development mode
python app.py
```

### Docker Installation

```bash
# Build and run with Docker
docker build -t dns-resolver .
docker run -p 60200:60200 dns-resolver

# Or use Docker Compose
docker compose up --build
```

---

## 📡 API Reference

### Resolve DNS Records

```http
GET /api/resolve?domain=<domain>&type=<type>&servers=<servers>
```

| Parameter | Type   | Required | Description                                      |
|-----------|--------|----------|--------------------------------------------------|
| domain    | string | Yes      | Domain name to resolve                           |
| type      | string | No       | Record type (A, AAAA, MX, etc.) Default: A       |
| servers   | string | No       | Comma-separated DNS server IPs                   |

**Example:**

```bash
curl "http://localhost:60200/api/resolve?domain=example.com&type=A" | jq
```

**Response:**

```json
{
  "domain": "example.com",
  "results": [
    {
      "record_type": "A",
      "answers": ["93.184.216.34"],
      "dns_servers": ["8.8.8.8", "1.1.1.1"],
      "latency_ms": {"8.8.8.8": 12.5, "1.1.1.1": 8.3},
      "ttl_remaining": 3600,
      "dnssec": "validated",
      "flags": {"aa": false, "ad": true, "ra": true, "rd": true}
    }
  ]
}
```

### DNS Trace

```http
GET /api/trace?domain=<domain>
```

Performs an iterative DNS trace from root servers to authoritative nameservers.

```bash
curl "http://localhost:60200/api/trace?domain=example.com" | jq
```

### Reverse DNS Lookup

```http
GET /api/reverse?ip=<ip>&servers=<servers>
```

```bash
curl "http://localhost:60200/api/reverse?ip=8.8.8.8" | jq
```

**Response:**

```json
{
  "ip": "8.8.8.8",
  "reverse_name": "8.8.8.8.in-addr.arpa",
  "hostnames": ["dns.google"],
  "latency_ms": 15.2
}
```

### Health Check

```http
GET /health
```

Returns service health status for monitoring and load balancers.

### Available DNS Servers

```http
GET /api/servers
```

Returns the list of default DNS servers available for selection.

---

## 🛡️ Advanced API Endpoints

### Email Security Analysis

```http
GET /api/email-security?domain=<domain>&dkim_selector=<selector>
```

Analyzes SPF, DKIM, and DMARC records for email security.

```bash
curl "http://localhost:60200/api/email-security?domain=google.com" | jq
```

### DNS Propagation Check

```http
GET /api/propagation?domain=<domain>&type=<type>
```

Checks DNS propagation across 16+ global DNS servers.

```bash
curl "http://localhost:60200/api/propagation?domain=example.com&type=A" | jq
```

### Blacklist Check

```http
GET /api/blacklist?ip=<ip>
```

Checks if an IP is listed on major DNS blacklists.

```bash
curl "http://localhost:60200/api/blacklist?ip=1.2.3.4" | jq
```

### DNS Security Audit

```http
GET /api/security-audit?domain=<domain>
```

Performs comprehensive DNS security audit with grading.

```bash
curl "http://localhost:60200/api/security-audit?domain=cloudflare.com" | jq
```

### Subdomain Scanner

```http
GET /api/subdomain-scan?domain=<domain>
```

Scans for common subdomains using DNS enumeration (130+ checks).

```bash
curl "http://localhost:60200/api/subdomain-scan?domain=github.com" | jq
```

### DNS Diff / Comparison

```http
GET /api/dns-diff?domain1=<domain1>&domain2=<domain2>&type=<type>
```

Compare DNS records between domains or across DNS servers. If `domain2` is omitted, compares `domain1` across multiple DNS servers.

```bash
# Compare across DNS servers
curl "http://localhost:60200/api/dns-diff?domain1=example.com&type=NS" | jq

# Compare two domains
curl "http://localhost:60200/api/dns-diff?domain1=google.com&domain2=cloudflare.com&type=MX" | jq
```

### Zone Info

```http
GET /api/zone-info?domain=<domain>
```

Gets complete DNS zone overview with service detection.

```bash
curl "http://localhost:60200/api/zone-info?domain=cloudflare.com" | jq
```

### DNS Server Benchmark

```http
GET /api/compare?domain=<domain>&type=<type>
```

Benchmarks and compares DNS server response times.

```bash
curl "http://localhost:60200/api/compare?domain=example.com" | jq
```

---

## ⚙️ Configuration

### Environment Variables

| Variable            | Description                              | Default        |
|---------------------|------------------------------------------|----------------|
| `DNS_SERVERS`       | Comma-separated DNS server IPs           | System default |
| `PORT`              | HTTP server port                         | 60200          |
| `LIMITER_STORAGE_URI` | Redis URI for rate limit storage       | In-memory      |

**Example `.env` file:**

```env
DNS_SERVERS=8.8.8.8,1.1.1.1,9.9.9.9
PORT=60200
LIMITER_STORAGE_URI=redis://localhost:6379
```

---

## 🖥️ Shell Integration

Add this function to your `.bashrc` or `.zshrc`:

```bash
dns_resolve() {
  local domain="$1"
  local type="${2:-A}"
  if [[ -z "$domain" ]]; then
    echo "Usage: dns_resolve <domain> [record_type]"
    return 1
  fi
  curl -s "http://localhost:60200/api/resolve?domain=$domain&type=$type" | jq
}
```

**Usage:**

```bash
dns_resolve example.com        # A record (default)
dns_resolve example.com MX     # MX records
dns_resolve example.com ALL    # All record types
```

---

## 🎨 UI Status Indicators

| Indicator                  | Meaning                        |
|----------------------------|--------------------------------|
| 🟢 Green border            | Valid records returned         |
| ⚪ Gray border             | Empty but valid response       |
| 🟡 Yellow border           | Record not found (NoAnswer)    |
| 🔴 Red border              | DNS Error (NXDOMAIN, etc.)     |
| 🛡️ Shield                 | DNSSEC validated               |
| ❓ Shield with question    | DNSSEC unverified              |
| ❌ Shield with X           | DNSSEC failed/bogus            |

---

## 🔒 Security

- Rate limiting (60 requests/minute for resolve, 30/minute for trace)
- Input validation and sanitization
- Security headers via Flask-Talisman
- Non-root container user
- See [SECURITY.md](SECURITY.md) for vulnerability reporting

---

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.
