# Shell Function Examples

Shell wrapper functions for the DNS HTTP Resolver API. These let you query DNS records from the command line using simple commands.

## Requirements

- `curl` - for HTTP requests
- `jq` - for JSON parsing
- DNS resolver app running on `localhost:60200`

## Installation

### Bash

Add to `~/.bashrc`:

```bash
source /path/to/dns-http-resolver/examples/bash_functions.sh
```

Or copy the contents directly into your `~/.bashrc`.

### Zsh

Add to `~/.zshrc`:

```zsh
source /path/to/dns-http-resolver/examples/zsh_functions.zsh
```

Or copy the contents directly into your `~/.zshrc`.

### Custom Server URL

If your resolver runs on a different host/port, set the environment variable:

```bash
export DNS_HTTP_RESOLVER_URL="http://192.168.1.100:60200"
```

## Available Commands

| Command | Usage | Description |
|---------|-------|-------------|
| `dns-http-resolve` | `dns-http-resolve <domain> [type]` | Basic DNS lookup (A, MX, TXT, etc.) |
| `dns-http-reverse` | `dns-http-reverse <ip>` | Reverse DNS (IP to hostname) |
| `dns-http-trace` | `dns-http-trace <domain>` | Trace DNS resolution path |
| `dns-http-propagation` | `dns-http-propagation <domain> [type]` | Check global propagation |
| `dns-http-raw` | `dns-http-raw <domain> [type]` | Full JSON response |
| `dns-http-mail` | `dns-http-mail <domain>` | Email security (SPF/DKIM/DMARC) |
| `dns-http-blacklist` | `dns-http-blacklist <ip>` | Blacklist/RBL check |
| `dns-http-security` | `dns-http-security <domain>` | Security audit |
| `dns-http-zone` | `dns-http-zone <domain>` | Zone info overview |
| `dns-http-subdomain` | `dns-http-subdomain <domain>` | Subdomain discovery |
| `dns-http-health` | `dns-http-health` | Check resolver service status |
| `dns-http-servers` | `dns-http-servers` | List available DNS servers |

## Examples

```bash
# A record lookup
dns-http-resolve google.com

# MX records
dns-http-resolve google.com MX

# TXT records (SPF, verification, etc.)
dns-http-resolve google.com TXT

# All nameservers
dns-http-resolve google.com NS

# Reverse lookup
dns-http-reverse 8.8.8.8

# Trace DNS resolution
dns-http-trace example.com

# Check if DNS has propagated globally
dns-http-propagation mynewdomain.com A

# Check email security configuration
dns-http-mail google.com

# Check if IP is blacklisted
dns-http-blacklist 192.0.2.1

# Full security audit
dns-http-security example.com

# Get all DNS records for a domain
dns-http-zone example.com

# Find subdomains
dns-http-subdomain example.com
```

## Scripting Examples

### Check if a record exists

```bash
if dns-http-resolve example.com A | grep -q "No records"; then
    echo "No A record found"
else
    echo "A record exists"
fi
```

### Get just the IP addresses

```bash
dns-http-raw google.com | jq -r '.results[].answers[]'
```

### Check multiple domains

```bash
for domain in google.com github.com example.com; do
    echo "=== $domain ==="
    dns-http-resolve "$domain"
done
```

### Export to CSV

```bash
dns-http-raw google.com | jq -r '.results[] | [.server, (.answers | join(";"))] | @csv'
```
