# DNS HTTP Resolver Functions for Zsh
# Add these to your ~/.zshrc or source this file directly
#
# Usage: source /path/to/zsh_functions.zsh
#
# Requires: curl, jq
# Make sure your DNS resolver app is running on localhost:60200

# Configuration - change this if your server is elsewhere
DNS_HTTP_RESOLVER_URL="${DNS_HTTP_RESOLVER_URL:-http://localhost:60200}"

# Basic DNS lookup: dns-http-resolve <domain> [type]
# Examples:
#   dns-http-resolve google.com
#   dns-http-resolve google.com MX
#   dns-http-resolve google.com TXT
dns-http-resolve() {
    local domain="$1"
    local type="${2:-A}"
    if [[ -z "$domain" ]]; then
        echo "Usage: dns-http-resolve <domain> [type]"
        echo "Types: A, AAAA, MX, NS, CNAME, TXT, SOA, PTR, SRV, CAA"
        return 1
    fi
    curl -s "${DNS_HTTP_RESOLVER_URL}/api/resolve?domain=${domain}&type=${type}" | jq -r '.results[] | "\(.server): \(.answers // ["No records"] | join(", "))"' 2>/dev/null || curl -s "${DNS_HTTP_RESOLVER_URL}/api/resolve?domain=${domain}&type=${type}" | jq
}

# Reverse DNS lookup: dns-http-reverse <ip>
# Examples:
#   dns-http-reverse 8.8.8.8
#   dns-http-reverse 1.1.1.1
dns-http-reverse() {
    if [[ -z "$1" ]]; then
        echo "Usage: dns-http-reverse <ip>"
        return 1
    fi
    curl -s "${DNS_HTTP_RESOLVER_URL}/api/reverse?ip=$1" | jq -r '.hostnames[]? // "No PTR record"' 2>/dev/null || curl -s "${DNS_HTTP_RESOLVER_URL}/api/reverse?ip=$1" | jq
}

# DNS trace: dns-http-trace <domain>
# Traces the DNS resolution path from root servers to authoritative nameservers
# Example:
#   dns-http-trace example.com
dns-http-trace() {
    if [[ -z "$1" ]]; then
        echo "Usage: dns-http-trace <domain>"
        return 1
    fi
    curl -s "${DNS_HTTP_RESOLVER_URL}/api/trace?domain=$1" | jq
}

# Check global propagation: dns-http-propagation <domain> [type]
# Checks DNS propagation across 16+ global DNS servers
# Examples:
#   dns-http-propagation example.com
#   dns-http-propagation example.com A
#   dns-http-propagation example.com MX
dns-http-propagation() {
    local domain="$1"
    local type="${2:-A}"
    if [[ -z "$domain" ]]; then
        echo "Usage: dns-http-propagation <domain> [type]"
        return 1
    fi
    curl -s "${DNS_HTTP_RESOLVER_URL}/api/propagation?domain=${domain}&type=${type}" | jq
}

# Full JSON output: dns-http-raw <domain> [type]
# Returns the complete API response for scripting/debugging
# Examples:
#   dns-http-raw google.com
#   dns-http-raw google.com MX
dns-http-raw() {
    local domain="$1"
    local type="${2:-A}"
    if [[ -z "$domain" ]]; then
        echo "Usage: dns-http-raw <domain> [type]"
        return 1
    fi
    curl -s "${DNS_HTTP_RESOLVER_URL}/api/resolve?domain=${domain}&type=${type}" | jq
}

# Email security check: dns-http-mail <domain>
# Analyzes SPF, DKIM, and DMARC records
# Example:
#   dns-http-mail google.com
dns-http-mail() {
    if [[ -z "$1" ]]; then
        echo "Usage: dns-http-mail <domain>"
        return 1
    fi
    curl -s "${DNS_HTTP_RESOLVER_URL}/api/email-security?domain=$1" | jq
}

# Blacklist check: dns-http-blacklist <ip>
# Checks if an IP is listed on DNS blacklists (RBLs)
# Example:
#   dns-http-blacklist 192.0.2.1
dns-http-blacklist() {
    if [[ -z "$1" ]]; then
        echo "Usage: dns-http-blacklist <ip>"
        return 1
    fi
    curl -s "${DNS_HTTP_RESOLVER_URL}/api/blacklist?ip=$1" | jq
}

# Security audit: dns-http-security <domain>
# Performs a comprehensive DNS security audit
# Example:
#   dns-http-security example.com
dns-http-security() {
    if [[ -z "$1" ]]; then
        echo "Usage: dns-http-security <domain>"
        return 1
    fi
    curl -s "${DNS_HTTP_RESOLVER_URL}/api/security-audit?domain=$1" | jq
}

# Zone info: dns-http-zone <domain>
# Gets complete DNS record overview with service detection
# Example:
#   dns-http-zone example.com
dns-http-zone() {
    if [[ -z "$1" ]]; then
        echo "Usage: dns-http-zone <domain>"
        return 1
    fi
    curl -s "${DNS_HTTP_RESOLVER_URL}/api/zone-info?domain=$1" | jq
}

# Subdomain scan: dns-http-subdomain <domain>
# Discovers common subdomains via DNS enumeration
# Example:
#   dns-http-subdomain example.com
dns-http-subdomain() {
    if [[ -z "$1" ]]; then
        echo "Usage: dns-http-subdomain <domain>"
        return 1
    fi
    curl -s "${DNS_HTTP_RESOLVER_URL}/api/subdomain-scan?domain=$1" | jq
}

# Health check: dns-http-health
# Checks if the DNS resolver service is running
dns-http-health() {
    curl -s "${DNS_HTTP_RESOLVER_URL}/health" | jq
}

# List available DNS servers: dns-http-servers
# Shows the DNS servers available for queries
dns-http-servers() {
    curl -s "${DNS_HTTP_RESOLVER_URL}/api/servers" | jq
}

echo "DNS HTTP Resolver functions loaded. Commands: dns-http-resolve, dns-http-reverse, dns-http-trace, etc."
