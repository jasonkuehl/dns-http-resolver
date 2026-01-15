# DNS Resolver

A DNS resolver tool with a web UI and JSON API that queries multiple DNS servers, detects differences, and highlights discrepancies.

## Features

- Lookup DNS records (A, AAAA, MX, NS, etc.)
- Show combined results from multiple DNS servers
- Highlight differences per field in JSON
- Summary of server responses with latency
- Async loading indicator
- Supports filtering and copying results
- Docker + Docker Compose support
- GitHub Actions for container build

---

## Getting Started

### 🐍 Install (Local Mode)

http://localhost:5000


```bash
pip install -r requirements.txt
python app.py


How the API work

GET /api/resolve?domain=example.com&type=A


curl "http://localhost:5000/api/resolve?domain=jasonkuehl.com&type=A" | jq

Resolve All Record Types
curl "http://localhost:5000/api/resolve?domain=example.com&type=ALL"


resonncse

{
  "domain":"example.com",
  "results":[{...}]
}


docker build

docker build -t dns-resolver .
docker run -p 5000:5000 -e DNS_SERVERS="8.8.8.8,1.1.1.1" dns-resolver
docker compose up --build



You can paste this into your .bashrc, .zshrc, or run it directly in your shell:

dns_resolve() {
  local domain="$1"
  local type="${2:-A}"
  if [[ -z "$domain" ]]; then
    echo "Usage: dns_resolve <domain> [record_type]"
    return 1
  fi

  curl -s "http://localhost:5000/api/resolve?domain=$domain&type=$type" | jq
}

output

dns_resolve example.com           # Default A record
dns_resolve example.com MX        # MX records
dns_resolve example.com ALL       # All supported types






| Type                            | Visual                     |
| ------------------------------- | -------------------------- |
| **Valid records returned**      | Green                      |
| **Empty but valid response**    | Gray                       |
| **Record not found (NoAnswer)** | Yellow                     |
| **DNS Error (NXDOMAIN, etc.)**  | Red                        |
| **DNSSEC Validated**            | Shield icon / green        |
| **DNSSEC Bogus**                | Shield icon with X / red   |
| **DNSSEC Unverified**           | Shield & question / yellow |



## DNSSEC and Caching

This resolver performs DNSSEC validation when possible, and shows it in the UI:
- 🛡️ – DNSSEC validated
- ❓ – DNSSEC unverified
- ❌ – DNSSEC failed

Responses are cached by TTL to reduce lookup load and speed up repeat queries.
