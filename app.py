"""dns-http-resolver

Lightweight Flask app providing HTTP endpoints to resolve DNS records
and perform iterative DNS traces. This module contains route handlers,
validation helpers, and the core DNS query/trace implementations.

The comments and docstrings explain the purpose of each function and
important blocks of logic for maintainability.
"""

import os
import time
import logging
import re
import random
from collections import Counter
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import dns.flags
import dns.exception
import dns.rcode
import ipaddress
from flask import Flask, jsonify, request, render_template
from dotenv import load_dotenv
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from concurrent.futures import ThreadPoolExecutor, as_completed


load_dotenv()


def parse_server_env(env_var: str, default: dict) -> dict:
    """Parse DNS server configuration from environment variable.
    
    Format: Name:IP pairs, one per line or separated by semicolons (;)
    Example:
        Google Primary:8.8.8.8
        Cloudflare:1.1.1.1
    
    Args:
        env_var: Environment variable name to read
        default: Default dictionary to return if env var is empty/invalid
    
    Returns:
        Dictionary mapping server names to IP addresses
    """
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return default
    
    servers = {}
    # Split on newlines or semicolons
    import re
    entries = re.split(r'[;\n]+', raw)
    for pair in entries:
        pair = pair.strip()
        if ":" in pair:
            # Split on last colon to handle names with colons (rare but possible)
            name, ip = pair.rsplit(":", 1)
            name = name.strip()
            ip = ip.strip()
            if name and ip:
                servers[name] = ip
    
    return servers if servers else default


app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Security headers / CSP
CSP = {
  "default-src": ["'self'"],
  "script-src": ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
  "style-src": ["'self'","'unsafe-inline'","https://cdnjs.cloudflare.com"]
}
# Disable automatic HTTP->HTTPS redirects for local/dev (gunicorn serving plain HTTP)
Talisman(app, content_security_policy=CSP, force_https=False)

# Rate limiting - use configured storage backend when provided to avoid in-memory warnings in prod
LIMITER_STORAGE = os.environ.get("LIMITER_STORAGE_URI")

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri=LIMITER_STORAGE if LIMITER_STORAGE else "memory://"
)

# Default DNS servers available for selection (loaded from env or fallback)
_DEFAULT_DNS_SERVERS_FALLBACK = {
    "Google Primary": "8.8.8.8",
    "Google Secondary": "8.8.4.4",
    "Cloudflare Primary": "1.1.1.1",
    "Cloudflare Secondary": "1.0.0.1",
    "Quad9 Primary": "9.9.9.9",
    "Quad9 Secondary": "149.112.112.112",
    "OpenDNS Primary": "208.67.222.222",
    "OpenDNS Secondary": "208.67.220.220",
}
DEFAULT_DNS_SERVERS = parse_server_env("DEFAULT_DNS_SERVERS", _DEFAULT_DNS_SERVERS_FALLBACK)

# DNS servers to query (comma or newline separated in ENV). If empty, use system resolver.
_dns_servers_raw = os.environ.get("DNS_SERVERS", "")
DNS_SERVERS = [s.strip() for s in re.split(r'[,\n]+', _dns_servers_raw) if s.strip()]
USE_SYSTEM_RESOLVER = len(DNS_SERVERS) == 0

# Old strict regex removed; use a permissive validator that accepts IPs, single-label hostnames, and FQDNs.
def is_valid_domain_input(s: str) -> bool:
    """Validate that the provided input is a reasonable domain name or IP.

    Accepts IPv4/IPv6 addresses and permissive hostnames/FQDNs. Rejects
    empty strings, inputs with spaces, or components that exceed DNS limits.

    Args:
        s: Input string supplied by the user (domain or IP).

    Returns:
        True if input looks like a valid domain or IP, False otherwise.
    """
    if not s:
        return False
    s = s.strip()
    if len(s) > 253 or " " in s:
        return False
    # Quickly accept valid IP addresses (IPv4/IPv6)
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        pass

    # Remove trailing dot (FQDN style) then validate each label
    if s.endswith("."):
        s = s[:-1]
    labels = s.split(".")
    for label in labels:
        # Enforce DNS label length rules
        if not (1 <= len(label) <= 63):
            return False
        # Only allow letters, digits, and hyphens in labels
        if not re.match(r"^[A-Za-z0-9-]+$", label):
            return False
        # Labels must not begin or end with a hyphen
        if label[0] == "-" or label[-1] == "-":
            return False
    return True

@app.route("/")
def home():
    """Render the homepage with the resolve UI."""
    return render_template("home.html")

@app.route("/resolve")
def resolve_page():
    """Render the manual DNS resolution UI page."""
    return render_template("resolve.html", dns_servers=DEFAULT_DNS_SERVERS)

@app.route("/trace")
def trace_page():
    """Render the DNS trace UI page where users can run iterative traces."""
    return render_template("trace.html")

@app.route("/readme")
def readme_page():
    """Show the repository README as an HTML page for convenience."""
    return render_template("readme.html")

@app.route("/email-security")
def email_security_page():
    """Render the email security analyzer page."""
    return render_template("email_security.html")

@app.route("/propagation")
def propagation_page():
    """Render the DNS propagation checker page."""
    return render_template("propagation.html")

@app.route("/blacklist")
def blacklist_page():
    """Render the blacklist checker page."""
    return render_template("blacklist.html")

@app.route("/security-audit")
def security_audit_page():
    """Render the DNS security audit page."""
    return render_template("security_audit.html")


@app.route("/zone-info")
def zone_info_page():
    """Render the zone info page."""
    return render_template("zone_info.html")

@app.route("/api/resolve")
@limiter.limit("60/minute")
def api_resolve():
    """HTTP API endpoint that resolves DNS records.

    Query parameters:
        - domain: the domain or IP to query (required)
        - type: DNS record type (default: A)
        - servers: optional comma-separated list of DNS server IPs to query

    The endpoint validates inputs, runs queries in parallel against the
    selected servers (or the system resolver), and returns grouped results.
    """

    domain = request.args.get("domain", "").strip().lower()
    rtype = request.args.get("type", "A").upper()
    servers_param = request.args.get("servers", "").strip()

    if not domain:
        return jsonify({"error": {"code": "BadRequest", "message": "No domain specified"}}), 400
    if not is_valid_domain_input(domain):
        return jsonify({"error": {"code": "BadRequest", "message": "Invalid domain format"}}), 400

    # Parse servers parameter (comma-separated list of IPs)
    # If not provided, use DNS_SERVERS from env or system resolver
    if servers_param:
        selected_servers = [s.strip() for s in servers_param.split(",") if s.strip()]
        # Validate all server IPs
        for srv in selected_servers:
            try:
                ipaddress.ip_address(srv)
            except ValueError:
                return jsonify({"error": {"code": "BadRequest", "message": f"Invalid server IP: {srv}"}}), 400
    else:
        selected_servers = DNS_SERVERS

    use_system = len(selected_servers) == 0

    logging.info("Resolve requested: domain=%s type=%s servers=%s from=%s",
                 domain, rtype, selected_servers if not use_system else "system", request.remote_addr)

    ALLOWED = {"A","AAAA","MX","NS","CNAME","TXT","SOA","PTR","SRV","CAA","DNSKEY","ALL"}
    if rtype not in ALLOWED:
        return jsonify({"error": {"code": "BadRequest", "message": f"Invalid type: {rtype}"}}), 400

    types = ["A","AAAA","MX","NS","CNAME","TXT","SOA","PTR","SRV","CAA","DNSKEY"] if rtype == "ALL" else [rtype]

    def query_server(server, t):
        # Prepare a result container for this server/type query
        entry = {
            "record_type": t,
            "dns_servers": [server] if server else [],
            "answers": [],
            "authority": [],
            "flags": {},
            "dnssec": None,
            "latency_ms": None,
            "ttl_remaining": 0,
            "error": None
        }

        # Select resolver: when server is falsy we use the system resolver
        try:
            if not server:
                resolver = dns.resolver.Resolver()  # configure=True reads /etc/resolv.conf
            else:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [server]

            # Explicitly disable resolver caching and set short timeouts
            resolver.cache = None
            resolver.timeout = 3
            resolver.lifetime = 3

            # Time the resolution for latency reporting
            start = time.time()
            answer = resolver.resolve(domain, t, raise_on_no_answer=False)
            entry["latency_ms"] = round((time.time() - start) * 1000, 2)

            # Extract answer RRs and TTL when present
            if answer.rrset is not None:
                entry["answers"] = [rr.to_text() for rr in answer]
                entry["ttl_remaining"] = answer.rrset.ttl or 0

            # Parse flags and DNSSEC AD bit (if present) from the underlying DNS response
            try:
                resp = getattr(answer, "response", None)
                if resp is not None:
                    entry["flags"] = {
                        "aa": bool(resp.flags & dns.flags.AA),
                        "ra": bool(resp.flags & dns.flags.RA),
                        "rd": bool(resp.flags & dns.flags.RD),
                        "ad": bool(resp.flags & dns.flags.AD)
                    }
                    entry["dnssec"] = "validated" if entry["flags"].get("ad") else "unverified"
            except Exception:
                logging.debug("Could not parse flags/dnssec", exc_info=True)

            # Collect authority section strings if available
            try:
                resp = getattr(answer, "response", None)
                if resp is not None and getattr(resp, "authority", None):
                    auth = []
                    for rrset in resp.authority:
                        for rr in rrset:
                            auth.append(rr.to_text())
                    entry["authority"] = auth
            except Exception:
                logging.debug("Could not parse authority", exc_info=True)

        except dns.resolver.NXDOMAIN:
            entry["error"] = "NXDOMAIN"
        except dns.resolver.Timeout:
            entry["error"] = "Timeout"
        except dns.resolver.NoAnswer:
            # Explicitly record empty answer sets
            entry["answers"] = []
        except dns.resolver.NoNameservers:
            entry["error"] = "No nameservers"
        except Exception as e:
            entry["error"] = str(e)
            logging.exception("DNS query failed for server=%s type=%s domain=%s", server, t, domain)
        return entry

    # Build task list: if using system resolver, run a single task with server=None
    raw_results = []
    try:
        with ThreadPoolExecutor(max_workers=min(16, max(1, len(selected_servers) * len(types)))) as ex:
            futures = []
            if use_system:
                for t in types:
                    futures.append(ex.submit(query_server, None, t))
            else:
                for t in types:
                    for server in selected_servers:
                        futures.append(ex.submit(query_server, server, t))
            for f in as_completed(futures):
                raw_results.append(f.result())
    except Exception:
        logging.exception("Parallel DNS queries failed")
        return jsonify({"error": {"code": "ServerError", "message": "DNS queries failed"}}), 500

    # Grouping logic (unchanged, simplified)
    def normalize_key(r):
        return (
            r["record_type"],
            tuple(sorted(r.get("answers", []))),
            tuple(sorted(r.get("authority", []))),
            tuple(sorted(r.get("flags", {}).items())),
            r.get("dnssec"),
            r.get("error")
        )

    grouped = {}
    for r in raw_results:
        key = normalize_key(r)
        if key not in grouped:
            grouped[key] = {
                "record_type": r["record_type"],
                "answers": sorted(r.get("answers", [])),
                "authority": sorted(r.get("authority", [])),
                "flags": r.get("flags", {}),
                "dnssec": r.get("dnssec"),
                "dns_servers": [],
                "latency_ms": {},
                "ttl_remaining": r.get("ttl_remaining", 0),
                "error": r.get("error")
            }
        grouped[key]["dns_servers"].extend(r["dns_servers"])
        for svr in r["dns_servers"]:
            grouped[key]["latency_ms"][svr] = r.get("latency_ms", 0)

    return jsonify({"domain": domain, "results": list(grouped.values())})

@app.route("/api/trace")
@limiter.limit("30/minute")
def api_trace():
    """Endpoint to perform an iterative DNS trace from root servers to authoritative servers.

    Validates the domain and delegates to `dns_trace` which performs the
    step-wise UDP queries to root / referral servers, returning the collected
    trace steps to the caller.
    """

    domain = request.args.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": {"code": "BadRequest", "message": "No domain provided"}}), 400
    if not is_valid_domain_input(domain):
        return jsonify({"error": {"code": "BadRequest", "message": "Invalid domain format"}}), 400
    logging.info("Trace requested: domain=%s from=%s", domain, request.remote_addr)
    try:
        trace_data = dns_trace(domain)
        return jsonify({"domain": domain, "trace": trace_data})
    except Exception as e:
        logging.exception("Trace error for domain=%s", domain)
        return jsonify({"error": {"code": "ServerError", "message": "Trace failed: " + str(e)}}), 500

def dns_trace(domain, max_steps=15):
    """Perform an iterative DNS trace starting from the root servers.

    The function sends UDP queries to root servers, inspects answer/authority/
    additional sections, and follows referrals by extracting IPs from the
    additional section. It returns a list of step dictionaries describing
    each server interaction.

    Args:
        domain: The domain name to trace.
        max_steps: Maximum number of trace steps to prevent infinite loops.

    Returns:
        A list of step dictionaries with server, response, and record details.
    """
    trace_steps = []

    # Root server IPs (a-m.root-servers.net)
    ROOT_SERVERS = [
        ("a.root-servers.net", "198.41.0.4"),
        ("b.root-servers.net", "199.9.14.201"),
        ("c.root-servers.net", "192.33.4.12"),
        ("d.root-servers.net", "199.7.91.13"),
        ("e.root-servers.net", "192.203.230.10"),
        ("f.root-servers.net", "192.5.5.241"),
        ("g.root-servers.net", "192.112.36.4"),
        ("h.root-servers.net", "198.97.190.53"),
        ("i.root-servers.net", "192.36.148.17"),
        ("j.root-servers.net", "192.58.128.30"),
        ("k.root-servers.net", "193.0.14.129"),
        ("l.root-servers.net", "199.7.83.42"),
        ("m.root-servers.net", "202.12.27.33")
    ]

    # Start with a random root server for load distribution
    root_name, root_ip = random.choice(ROOT_SERVERS)
    servers_to_try = [(root_name, root_ip)]
    visited = set()

    step_count = 1
    while servers_to_try and step_count <= max_steps:
        server_name, server_ip = servers_to_try.pop(0)
        if server_ip in visited:
            continue
        visited.add(server_ip)

        step = {
            "step": step_count,
            "server": server_ip,
            "server_name": server_name,
            "response_code": None,
            "answer": [],
            "authority": [],
            "additional": [],
            "latency_ms": None,
            "is_authoritative": False
        }

        try:
            # Query for A record (ANY is often blocked/limited)
            q = dns.message.make_query(domain, dns.rdatatype.A, use_edns=True)
            start_time = time.time()
            r = dns.query.udp(q, server_ip, timeout=3)
            step["latency_ms"] = round((time.time() - start_time) * 1000, 2)

            step["response_code"] = dns.rcode.to_text(r.rcode())
            step["is_authoritative"] = bool(r.flags & dns.flags.AA)

            # Collect answer section
            for rrset in r.answer:
                for rr in rrset:
                    step["answer"].append({
                        "name": rrset.name.to_text(),
                        "type": dns.rdatatype.to_text(rrset.rdtype),
                        "ttl": rrset.ttl,
                        "data": rr.to_text()
                    })

            # Collect authority section (NS records)
            for rrset in r.authority:
                for rr in rrset:
                    step["authority"].append({
                        "name": rrset.name.to_text(),
                        "type": dns.rdatatype.to_text(rrset.rdtype),
                        "ttl": rrset.ttl,
                        "data": rr.to_text()
                    })

            # Collect additional section (glue records)
            glue_records = {}
            for rrset in r.additional:
                for rr in rrset:
                    rec_data = {
                        "name": rrset.name.to_text(),
                        "type": dns.rdatatype.to_text(rrset.rdtype),
                        "ttl": rrset.ttl,
                        "data": rr.to_text()
                    }
                    step["additional"].append(rec_data)
                    # Track A records for next hop
                    if rrset.rdtype == dns.rdatatype.A:
                        glue_records[rrset.name.to_text().rstrip(".")] = rr.to_text()

            trace_steps.append(step)

            # If we got an answer or authoritative response, we're done
            if step["answer"] or step["is_authoritative"]:
                break

            # Follow referrals: use glue records to find next nameserver
            for auth in step["authority"]:
                if auth["type"] == "NS":
                    ns_name = auth["data"].rstrip(".")
                    if ns_name in glue_records:
                        servers_to_try.append((ns_name, glue_records[ns_name]))

            step_count += 1

        except dns.exception.Timeout:
            step["error"] = "Query timed out"
            trace_steps.append(step)
            step_count += 1
        except Exception as e:
            step["error"] = str(e)
            trace_steps.append(step)
            logging.warning(f"Trace step {step_count} failed: {e}")
            step_count += 1

    return trace_steps

@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/health")
def health_check():
    """Health check endpoint for container orchestration and load balancers."""
    return jsonify({
        "status": "healthy",
        "service": "dns-http-resolver",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    })


@app.route("/api/servers")
def api_servers():
    """Return available default DNS servers for UI selection."""
    return jsonify({
        "servers": DEFAULT_DNS_SERVERS,
        "configured": DNS_SERVERS if DNS_SERVERS else "system"
    })


@app.route("/api/reverse")
@limiter.limit("30/minute")
def api_reverse():
    """Reverse DNS lookup for an IP address.

    Query parameters:
        - ip: IPv4 or IPv6 address to perform reverse lookup on
        - servers: optional comma-separated list of DNS server IPs

    Returns the PTR record(s) for the given IP address.
    """
    ip_addr = request.args.get("ip", "").strip()
    servers_param = request.args.get("servers", "").strip()

    if not ip_addr:
        return jsonify({"error": {"code": "BadRequest", "message": "No IP address specified"}}), 400

    # Validate IP address
    try:
        parsed_ip = ipaddress.ip_address(ip_addr)
    except ValueError:
        return jsonify({"error": {"code": "BadRequest", "message": "Invalid IP address format"}}), 400

    # Convert to reverse DNS name
    reverse_name = parsed_ip.reverse_pointer

    logging.info("Reverse lookup requested: ip=%s from=%s", ip_addr, request.remote_addr)

    # Parse servers
    if servers_param:
        selected_servers = [s.strip() for s in servers_param.split(",") if s.strip()]
        for srv in selected_servers:
            try:
                ipaddress.ip_address(srv)
            except ValueError:
                return jsonify({"error": {"code": "BadRequest", "message": f"Invalid server IP: {srv}"}}), 400
    else:
        selected_servers = DNS_SERVERS

    use_system = len(selected_servers) == 0

    results = []
    try:
        if use_system:
            resolver = dns.resolver.Resolver()
        else:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = selected_servers

        resolver.timeout = 5
        resolver.lifetime = 5

        start = time.time()
        answer = resolver.resolve(reverse_name, "PTR", raise_on_no_answer=False)
        latency = round((time.time() - start) * 1000, 2)

        if answer.rrset is not None:
            results = [rr.to_text().rstrip(".") for rr in answer]

        return jsonify({
            "ip": ip_addr,
            "reverse_name": reverse_name,
            "hostnames": results,
            "latency_ms": latency,
            "dns_servers": selected_servers if not use_system else ["system"]
        })

    except dns.resolver.NXDOMAIN:
        return jsonify({"ip": ip_addr, "reverse_name": reverse_name, "hostnames": [], "error": "No PTR record found"})
    except dns.resolver.Timeout:
        return jsonify({"error": {"code": "Timeout", "message": "DNS query timed out"}}), 504
    except Exception as e:
        logging.exception("Reverse lookup failed for ip=%s", ip_addr)
        return jsonify({"error": {"code": "ServerError", "message": str(e)}}), 500


# =============================================================================
# Email Security Analysis (SPF, DKIM, DMARC)
# =============================================================================

# Global DNS servers for propagation checking (loaded from env or fallback)
_GLOBAL_DNS_SERVERS_FALLBACK = {
    "Google (US)": "8.8.8.8",
    "Cloudflare (US)": "1.1.1.1",
    "Quad9 (US)": "9.9.9.9",
    "OpenDNS (US)": "208.67.222.222",
    "Level3 (US)": "4.2.2.1",
    "Comodo (US)": "8.26.56.26",
    "CleanBrowsing (US)": "185.228.168.9",
    "AdGuard (Cyprus)": "94.140.14.14",
    "Yandex (Russia)": "77.88.8.8",
    "DNS.Watch (Germany)": "84.200.69.80",
    "Freenom (Netherlands)": "80.80.80.80",
    "UncensoredDNS (Denmark)": "91.239.100.100",
    "Hurricane Electric (US)": "74.82.42.42",
    "puntCAT (Spain)": "109.69.8.51",
    "Neustar (US)": "156.154.70.5",
    "SafeDNS (US)": "195.46.39.39",
}
GLOBAL_DNS_SERVERS = parse_server_env("GLOBAL_DNS_SERVERS", _GLOBAL_DNS_SERVERS_FALLBACK)


def parse_spf_record(txt_record):
    """Parse and analyze an SPF record."""
    analysis = {
        "raw": txt_record,
        "version": None,
        "mechanisms": [],
        "modifiers": [],
        "includes": [],
        "ip4": [],
        "ip6": [],
        "all_mechanism": None,
        "warnings": [],
        "is_valid": True
    }

    if not txt_record.startswith("v=spf1"):
        analysis["is_valid"] = False
        analysis["warnings"].append("Missing v=spf1 version tag")
        return analysis

    analysis["version"] = "spf1"
    parts = txt_record.split()

    dns_lookups = 0
    for part in parts[1:]:  # Skip v=spf1
        part_lower = part.lower()

        if part_lower.startswith("include:"):
            domain = part[8:]
            analysis["includes"].append(domain)
            analysis["mechanisms"].append({"type": "include", "value": domain})
            dns_lookups += 1
        elif part_lower.startswith("ip4:"):
            ip = part[4:]
            analysis["ip4"].append(ip)
            analysis["mechanisms"].append({"type": "ip4", "value": ip})
        elif part_lower.startswith("ip6:"):
            ip = part[4:]
            analysis["ip6"].append(ip)
            analysis["mechanisms"].append({"type": "ip6", "value": ip})
        elif part_lower.startswith("a:") or part_lower == "a":
            analysis["mechanisms"].append({"type": "a", "value": part[2:] if ":" in part else ""})
            dns_lookups += 1
        elif part_lower.startswith("mx:") or part_lower == "mx":
            analysis["mechanisms"].append({"type": "mx", "value": part[3:] if ":" in part else ""})
            dns_lookups += 1
        elif part_lower.startswith("ptr"):
            analysis["mechanisms"].append({"type": "ptr", "value": part[4:] if ":" in part else ""})
            analysis["warnings"].append("PTR mechanism is deprecated and slow")
            dns_lookups += 1
        elif part_lower.startswith("exists:"):
            analysis["mechanisms"].append({"type": "exists", "value": part[7:]})
            dns_lookups += 1
        elif part_lower.startswith("redirect="):
            analysis["modifiers"].append({"type": "redirect", "value": part[9:]})
            dns_lookups += 1
        elif part_lower.startswith("exp="):
            analysis["modifiers"].append({"type": "exp", "value": part[4:]})
        elif part_lower in ["~all", "-all", "+all", "?all"]:
            analysis["all_mechanism"] = part_lower
            if part_lower == "+all":
                analysis["warnings"].append("+all allows anyone to send email (DANGEROUS)")
            elif part_lower == "?all":
                analysis["warnings"].append("?all is neutral and provides no protection")

    if dns_lookups > 10:
        analysis["warnings"].append(f"Too many DNS lookups ({dns_lookups}). SPF limit is 10.")

    if not analysis["all_mechanism"]:
        analysis["warnings"].append("Missing 'all' mechanism at the end")

    return analysis


def parse_dmarc_record(txt_record):
    """Parse and analyze a DMARC record."""
    analysis = {
        "raw": txt_record,
        "version": None,
        "policy": None,
        "subdomain_policy": None,
        "pct": 100,
        "rua": [],
        "ruf": [],
        "adkim": "r",
        "aspf": "r",
        "fo": "0",
        "warnings": [],
        "is_valid": True
    }

    if not txt_record.lower().startswith("v=dmarc1"):
        analysis["is_valid"] = False
        analysis["warnings"].append("Missing v=DMARC1 version tag")
        return analysis

    analysis["version"] = "DMARC1"

    # Parse key=value pairs
    parts = txt_record.split(";")
    for part in parts:
        part = part.strip()
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip()

        if key == "p":
            analysis["policy"] = value.lower()
            if value.lower() not in ["none", "quarantine", "reject"]:
                analysis["warnings"].append(f"Invalid policy: {value}")
        elif key == "sp":
            analysis["subdomain_policy"] = value.lower()
        elif key == "pct":
            try:
                analysis["pct"] = int(value)
            except ValueError:
                analysis["warnings"].append(f"Invalid pct value: {value}")
        elif key == "rua":
            analysis["rua"] = [v.strip() for v in value.split(",")]
        elif key == "ruf":
            analysis["ruf"] = [v.strip() for v in value.split(",")]
        elif key == "adkim":
            analysis["adkim"] = value.lower()
        elif key == "aspf":
            analysis["aspf"] = value.lower()
        elif key == "fo":
            analysis["fo"] = value

    if not analysis["policy"]:
        analysis["warnings"].append("Missing required 'p' (policy) tag")
        analysis["is_valid"] = False

    if analysis["policy"] == "none":
        analysis["warnings"].append("Policy is 'none' - DMARC is in monitoring mode only")

    if not analysis["rua"]:
        analysis["warnings"].append("No aggregate report URI (rua) specified")

    if analysis["pct"] < 100:
        analysis["warnings"].append(f"Only {analysis['pct']}% of messages are subject to DMARC")

    return analysis


@app.route("/api/email-security")
@limiter.limit("30/minute")
def api_email_security():
    """Analyze email security records (SPF, DKIM, DMARC) for a domain."""
    domain = request.args.get("domain", "").strip().lower()
    dkim_selector = request.args.get("dkim_selector", "").strip()

    if not domain:
        return jsonify({"error": {"code": "BadRequest", "message": "No domain specified"}}), 400
    if not is_valid_domain_input(domain):
        return jsonify({"error": {"code": "BadRequest", "message": "Invalid domain format"}}), 400

    logging.info("Email security check: domain=%s from=%s", domain, request.remote_addr)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    results = {
        "domain": domain,
        "spf": {"found": False, "records": [], "analysis": None},
        "dmarc": {"found": False, "record": None, "analysis": None},
        "dkim": {"found": False, "record": None, "selector": dkim_selector},
        "mx": {"found": False, "records": []},
        "score": 0,
        "recommendations": []
    }

    # Check SPF
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                results["spf"]["found"] = True
                results["spf"]["records"].append(txt)
                results["spf"]["analysis"] = parse_spf_record(txt)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except Exception as e:
        logging.warning(f"SPF lookup failed: {e}")

    # Check DMARC
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=dmarc1"):
                results["dmarc"]["found"] = True
                results["dmarc"]["record"] = txt
                results["dmarc"]["analysis"] = parse_dmarc_record(txt)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except Exception as e:
        logging.warning(f"DMARC lookup failed: {e}")

    # Check DKIM if selector provided
    if dkim_selector:
        try:
            dkim_domain = f"{dkim_selector}._domainkey.{domain}"
            answers = resolver.resolve(dkim_domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                results["dkim"]["found"] = True
                results["dkim"]["record"] = txt
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            logging.warning(f"DKIM lookup failed: {e}")

    # Check MX records
    try:
        answers = resolver.resolve(domain, "MX")
        for rdata in answers:
            results["mx"]["found"] = True
            results["mx"]["records"].append({
                "priority": rdata.preference,
                "host": rdata.exchange.to_text().rstrip(".")
            })
        results["mx"]["records"].sort(key=lambda x: x["priority"])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except Exception as e:
        logging.warning(f"MX lookup failed: {e}")

    # Calculate score and recommendations
    score = 0
    if results["spf"]["found"]:
        score += 25
        if results["spf"]["analysis"] and results["spf"]["analysis"]["all_mechanism"] in ["-all", "~all"]:
            score += 10
    else:
        results["recommendations"].append("Add an SPF record to prevent email spoofing")

    if results["dmarc"]["found"]:
        score += 25
        if results["dmarc"]["analysis"]:
            if results["dmarc"]["analysis"]["policy"] == "reject":
                score += 15
            elif results["dmarc"]["analysis"]["policy"] == "quarantine":
                score += 10
            if results["dmarc"]["analysis"]["rua"]:
                score += 5
    else:
        results["recommendations"].append("Add a DMARC record for email authentication policy")

    if results["dkim"]["found"]:
        score += 20
    elif dkim_selector:
        results["recommendations"].append(f"DKIM record not found for selector '{dkim_selector}'")

    if results["mx"]["found"]:
        score += 5

    results["score"] = min(score, 100)

    if results["score"] < 50:
        results["recommendations"].append("Email security is weak - implement SPF, DKIM, and DMARC")

    return jsonify(results)


# =============================================================================
# DNS Propagation Checker
# =============================================================================

@app.route("/api/propagation")
@limiter.limit("20/minute")
def api_propagation():
    """Check DNS propagation across global DNS servers."""
    domain = request.args.get("domain", "").strip().lower()
    rtype = request.args.get("type", "A").upper()

    if not domain:
        return jsonify({"error": {"code": "BadRequest", "message": "No domain specified"}}), 400
    if not is_valid_domain_input(domain):
        return jsonify({"error": {"code": "BadRequest", "message": "Invalid domain format"}}), 400

    ALLOWED = {"A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "CAA"}
    if rtype not in ALLOWED:
        return jsonify({"error": {"code": "BadRequest", "message": f"Invalid type: {rtype}"}}), 400

    logging.info("Propagation check: domain=%s type=%s from=%s", domain, rtype, request.remote_addr)

    def query_server(name, ip):
        result = {
            "server_name": name,
            "server_ip": ip,
            "answers": [],
            "ttl": None,
            "latency_ms": None,
            "error": None,
            "status": "ok"
        }
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ip]
            resolver.timeout = 5
            resolver.lifetime = 5

            start = time.time()
            answer = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            result["latency_ms"] = round((time.time() - start) * 1000, 2)

            if answer.rrset is not None:
                result["answers"] = sorted([rr.to_text() for rr in answer])
                result["ttl"] = answer.rrset.ttl
            else:
                result["status"] = "empty"
        except dns.resolver.NXDOMAIN:
            result["error"] = "NXDOMAIN"
            result["status"] = "nxdomain"
        except dns.resolver.Timeout:
            result["error"] = "Timeout"
            result["status"] = "timeout"
        except dns.resolver.NoNameservers:
            result["error"] = "No nameservers"
            result["status"] = "error"
        except Exception as e:
            result["error"] = str(e)
            result["status"] = "error"
        return result

    results = []
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {executor.submit(query_server, name, ip): name for name, ip in GLOBAL_DNS_SERVERS.items()}
        for future in as_completed(futures):
            results.append(future.result())

    # Analyze propagation
    all_answers = [tuple(r["answers"]) for r in results if r["answers"]]
    unique_answers = set(all_answers)
    is_propagated = len(unique_answers) <= 1 and len(all_answers) > 0

    # Find most common answer
    most_common = None
    if all_answers:
        counter = Counter(all_answers)
        most_common = list(counter.most_common(1)[0][0]) if counter else None

    return jsonify({
        "domain": domain,
        "record_type": rtype,
        "is_fully_propagated": is_propagated,
        "unique_responses": len(unique_answers),
        "servers_checked": len(results),
        "servers_responding": len([r for r in results if r["answers"]]),
        "most_common_answer": most_common,
        "results": sorted(results, key=lambda x: x["server_name"])
    })


# =============================================================================
# Blacklist (RBL) Checker
# =============================================================================

BLACKLISTS = [
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("Spamhaus DBL", "dbl.spamhaus.org"),
    ("Barracuda", "b.barracudacentral.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("SORBS", "dnsbl.sorbs.net"),
    ("UCEPROTECT L1", "dnsbl-1.uceprotect.net"),
    ("UCEPROTECT L2", "dnsbl-2.uceprotect.net"),
    ("Composite BL", "cbl.abuseat.org"),
    ("Truncate", "truncate.gbudb.net"),
    ("PSBL", "psbl.surriel.com"),
    ("Mailspike", "bl.mailspike.net"),
    ("JustSpam", "dnsbl.justspam.org"),
]


@app.route("/api/blacklist")
@limiter.limit("20/minute")
def api_blacklist():
    """Check if an IP address is listed on DNS blacklists."""
    ip_addr = request.args.get("ip", "").strip()

    if not ip_addr:
        return jsonify({"error": {"code": "BadRequest", "message": "No IP address specified"}}), 400

    try:
        parsed_ip = ipaddress.ip_address(ip_addr)
        if parsed_ip.version != 4:
            return jsonify({"error": {"code": "BadRequest", "message": "Only IPv4 addresses supported for blacklist check"}}), 400
    except ValueError:
        return jsonify({"error": {"code": "BadRequest", "message": "Invalid IP address format"}}), 400

    logging.info("Blacklist check: ip=%s from=%s", ip_addr, request.remote_addr)

    # Reverse the IP for DNSBL queries
    reversed_ip = ".".join(reversed(ip_addr.split(".")))

    def check_blacklist(name, bl_domain):
        result = {
            "blacklist": name,
            "listed": False,
            "response": None,
            "latency_ms": None
        }
        try:
            query = f"{reversed_ip}.{bl_domain}"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3

            start = time.time()
            answers = resolver.resolve(query, "A")
            result["latency_ms"] = round((time.time() - start) * 1000, 2)
            result["listed"] = True
            result["response"] = [rr.to_text() for rr in answers]
        except dns.resolver.NXDOMAIN:
            result["listed"] = False
        except dns.resolver.Timeout:
            result["response"] = "Timeout"
        except Exception:
            pass
        return result

    results = []
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(check_blacklist, name, bl): name for name, bl in BLACKLISTS}
        for future in as_completed(futures):
            results.append(future.result())

    listed_count = sum(1 for r in results if r["listed"])

    return jsonify({
        "ip": ip_addr,
        "total_blacklists": len(BLACKLISTS),
        "listed_count": listed_count,
        "clean": listed_count == 0,
        "results": sorted(results, key=lambda x: (not x["listed"], x["blacklist"]))
    })


# =============================================================================
# DNS Security Audit
# =============================================================================

@app.route("/api/security-audit")
@limiter.limit("10/minute")
def api_security_audit():
    """Perform a comprehensive DNS security audit for a domain."""
    domain = request.args.get("domain", "").strip().lower()

    if not domain:
        return jsonify({"error": {"code": "BadRequest", "message": "No domain specified"}}), 400
    if not is_valid_domain_input(domain):
        return jsonify({"error": {"code": "BadRequest", "message": "Invalid domain format"}}), 400

    logging.info("Security audit: domain=%s from=%s", domain, request.remote_addr)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    audit = {
        "domain": domain,
        "checks": [],
        "score": 0,
        "grade": "F",
        "summary": {
            "passed": 0,
            "warnings": 0,
            "failed": 0
        }
    }

    def add_check(name, status, message, details=None):
        check = {"name": name, "status": status, "message": message}
        if details:
            check["details"] = details
        audit["checks"].append(check)
        if status == "pass":
            audit["summary"]["passed"] += 1
        elif status == "warning":
            audit["summary"]["warnings"] += 1
        else:
            audit["summary"]["failed"] += 1

    # Check 1: NS Records
    try:
        ns_answers = resolver.resolve(domain, "NS")
        ns_records = [rr.to_text().rstrip(".") for rr in ns_answers]
        if len(ns_records) >= 2:
            add_check("Multiple NS Records", "pass", f"Found {len(ns_records)} nameservers", ns_records)
        else:
            add_check("Multiple NS Records", "warning", "Only 1 nameserver found - add redundancy", ns_records)
    except Exception as e:
        add_check("NS Records", "fail", f"Could not retrieve NS records: {e}")

    # Check 2: SOA Record
    try:
        soa_answers = resolver.resolve(domain, "SOA")
        soa = soa_answers[0]
        soa_data = {
            "mname": soa.mname.to_text().rstrip("."),
            "rname": soa.rname.to_text().rstrip("."),
            "serial": soa.serial,
            "refresh": soa.refresh,
            "retry": soa.retry,
            "expire": soa.expire,
            "minimum": soa.minimum
        }
        add_check("SOA Record", "pass", "SOA record found", soa_data)
    except Exception as e:
        add_check("SOA Record", "fail", f"Could not retrieve SOA record: {e}")

    # Check 3: DNSSEC
    try:
        # Try to get DNSKEY records
        dnskey_answers = resolver.resolve(domain, "DNSKEY")
        add_check("DNSSEC", "pass", "DNSSEC is enabled", {"dnskey_count": len(list(dnskey_answers))})
    except dns.resolver.NoAnswer:
        add_check("DNSSEC", "warning", "DNSSEC is not enabled for this domain")
    except dns.resolver.NXDOMAIN:
        add_check("DNSSEC", "fail", "Domain does not exist")
    except Exception:
        add_check("DNSSEC", "warning", "Could not verify DNSSEC status")

    # Check 4: CAA Records
    try:
        caa_answers = resolver.resolve(domain, "CAA")
        caa_records = [rr.to_text() for rr in caa_answers]
        add_check("CAA Records", "pass", "CAA records found - certificate issuance is controlled", caa_records)
    except dns.resolver.NoAnswer:
        add_check("CAA Records", "warning", "No CAA records - any CA can issue certificates")
    except Exception:
        add_check("CAA Records", "warning", "Could not check CAA records")

    # Check 5: SPF Record
    try:
        txt_answers = resolver.resolve(domain, "TXT")
        spf_found = False
        for rdata in txt_answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                spf_found = True
                if "-all" in txt.lower():
                    add_check("SPF Record", "pass", "SPF record with strict policy (-all)", txt)
                elif "~all" in txt.lower():
                    add_check("SPF Record", "pass", "SPF record with softfail policy (~all)", txt)
                else:
                    add_check("SPF Record", "warning", "SPF record exists but policy may be weak", txt)
                break
        if not spf_found:
            add_check("SPF Record", "fail", "No SPF record found - email spoofing is possible")
    except Exception:
        add_check("SPF Record", "fail", "Could not check SPF record")

    # Check 6: DMARC Record
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=dmarc1"):
                if "p=reject" in txt.lower():
                    add_check("DMARC Record", "pass", "DMARC with reject policy", txt)
                elif "p=quarantine" in txt.lower():
                    add_check("DMARC Record", "pass", "DMARC with quarantine policy", txt)
                else:
                    add_check("DMARC Record", "warning", "DMARC exists but policy is 'none'", txt)
                break
    except dns.resolver.NXDOMAIN:
        add_check("DMARC Record", "fail", "No DMARC record found")
    except Exception:
        add_check("DMARC Record", "warning", "Could not check DMARC record")

    # Check 7: MX Records
    try:
        mx_answers = resolver.resolve(domain, "MX")
        mx_records = [{"priority": rr.preference, "host": rr.exchange.to_text().rstrip(".")} for rr in mx_answers]
        if mx_records:
            add_check("MX Records", "pass", f"Found {len(mx_records)} MX records", mx_records)
        else:
            add_check("MX Records", "warning", "No MX records found")
    except Exception:
        add_check("MX Records", "warning", "Could not check MX records")

    # Check 8: Zone Transfer (AXFR) - Should be denied
    try:
        ns_answers = resolver.resolve(domain, "NS")
        axfr_vulnerable = False
        for ns in ns_answers:
            ns_ip = str(ns.target).rstrip(".")
            try:
                # Try to get IP of nameserver
                ns_a = resolver.resolve(ns_ip, "A")
                ns_ip_addr = ns_a[0].to_text()
                # Attempt zone transfer
                xfr = dns.query.xfr(ns_ip_addr, domain, timeout=3)
                for _ in xfr:
                    axfr_vulnerable = True
                    break
                if axfr_vulnerable:
                    break
            except Exception:
                pass
        if axfr_vulnerable:
            add_check("Zone Transfer (AXFR)", "fail", "Zone transfer is ALLOWED - major security risk!")
        else:
            add_check("Zone Transfer (AXFR)", "pass", "Zone transfer is properly restricted")
    except Exception:
        add_check("Zone Transfer (AXFR)", "pass", "Zone transfer appears restricted")

    # Check 9: Open Resolver Check (for NS)
    add_check("Open Resolver", "pass", "Skipped - requires direct NS testing")

    # Calculate score
    total_checks = len(audit["checks"])
    if total_checks > 0:
        score = (audit["summary"]["passed"] * 100 + audit["summary"]["warnings"] * 50) / total_checks
        audit["score"] = round(score)

        if score >= 90:
            audit["grade"] = "A"
        elif score >= 80:
            audit["grade"] = "B"
        elif score >= 70:
            audit["grade"] = "C"
        elif score >= 60:
            audit["grade"] = "D"
        else:
            audit["grade"] = "F"

    return jsonify(audit)


# =============================================================================
# Compare DNS Servers
# =============================================================================

@app.route("/api/compare")
@limiter.limit("30/minute")
def api_compare():
    """Compare response times and results across DNS providers."""
    domain = request.args.get("domain", "").strip().lower()
    iterations = min(int(request.args.get("iterations", 3)), 10)

    if not domain:
        return jsonify({"error": {"code": "BadRequest", "message": "No domain specified"}}), 400
    if not is_valid_domain_input(domain):
        return jsonify({"error": {"code": "BadRequest", "message": "Invalid domain format"}}), 400

    logging.info("DNS compare: domain=%s iterations=%d from=%s", domain, iterations, request.remote_addr)

    def benchmark_server(name, ip):
        latencies = []
        answers = None
        errors = 0

        for _ in range(iterations):
            try:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [ip]
                resolver.timeout = 5
                resolver.lifetime = 5

                start = time.time()
                answer = resolver.resolve(domain, "A", raise_on_no_answer=False)
                latency = (time.time() - start) * 1000
                latencies.append(latency)

                if answer.rrset is not None and answers is None:
                    answers = sorted([rr.to_text() for rr in answer])
            except Exception:
                errors += 1

        if latencies:
            return {
                "server_name": name,
                "server_ip": ip,
                "min_ms": round(min(latencies), 2),
                "max_ms": round(max(latencies), 2),
                "avg_ms": round(sum(latencies) / len(latencies), 2),
                "answers": answers,
                "errors": errors,
                "success_rate": round((iterations - errors) / iterations * 100, 1)
            }
        return {
            "server_name": name,
            "server_ip": ip,
            "min_ms": None,
            "max_ms": None,
            "avg_ms": None,
            "answers": None,
            "errors": iterations,
            "success_rate": 0
        }

    results = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(benchmark_server, name, ip): name for name, ip in DEFAULT_DNS_SERVERS.items()}
        for future in as_completed(futures):
            results.append(future.result())

    # Sort by average latency
    results.sort(key=lambda x: x["avg_ms"] if x["avg_ms"] is not None else float("inf"))

    # Find fastest
    fastest = results[0] if results and results[0]["avg_ms"] is not None else None

    return jsonify({
        "domain": domain,
        "iterations": iterations,
        "fastest_server": fastest["server_name"] if fastest else None,
        "fastest_latency_ms": fastest["avg_ms"] if fastest else None,
        "results": results
    })


# Common subdomains for discovery
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "proxy", "vpn", "gateway", "router",
    "firewall", "admin", "administrator", "api", "app", "apps", "mobile",
    "m", "dev", "development", "staging", "stage", "test", "testing", "beta",
    "alpha", "demo", "sandbox", "uat", "qa", "prod", "production", "live",
    "www2", "www3", "cdn", "static", "assets", "media", "img", "images",
    "video", "videos", "download", "downloads", "files", "upload", "uploads",
    "backup", "backups", "db", "database", "mysql", "mssql", "postgres",
    "postgresql", "oracle", "mongodb", "redis", "memcached", "elastic",
    "elasticsearch", "kibana", "grafana", "prometheus", "jenkins", "gitlab",
    "github", "bitbucket", "jira", "confluence", "wiki", "docs", "doc",
    "documentation", "help", "support", "status", "monitor", "monitoring",
    "nagios", "zabbix", "log", "logs", "logging", "syslog", "audit",
    "secure", "security", "ssl", "auth", "authentication", "login", "sso",
    "oauth", "ldap", "ad", "exchange", "owa", "autodiscover", "lyncdiscover",
    "sip", "meet", "meeting", "conference", "chat", "slack", "teams",
    "calendar", "cal", "cloud", "aws", "azure", "gcp", "s3", "storage",
    "nas", "san", "nfs", "share", "remote", "rdp", "ssh", "sftp", "git",
    "svn", "repo", "repository", "docker", "kubernetes", "k8s", "rancher",
    "portal", "intranet", "extranet", "internal", "external", "public",
    "private", "corp", "corporate", "office", "hq", "headquarters", "shop",
    "store", "ecommerce", "cart", "checkout", "payment", "pay", "billing",
    "invoice", "crm", "erp", "hr", "finance", "accounting", "sales",
    "marketing", "blog", "news", "forum", "community", "social", "analytics"
]


@app.route("/subdomain-scan")
def subdomain_scan_page():
    """Render subdomain scanner page."""
    return render_template("subdomain_scan.html")


@app.route("/dns-diff")
def dns_diff_page():
    """Render DNS diff/comparison page."""
    return render_template("dns_diff.html")


@app.route("/api/subdomain-scan")
@limiter.limit("10 per minute")
def api_subdomain_scan():
    """Scan for common subdomains of a domain.
    
    This performs DNS lookups for common subdomain prefixes to discover
    active subdomains. Useful for reconnaissance and asset discovery.
    """
    domain = request.args.get("domain", "").strip().lower()
    
    if not domain or not is_valid_domain_input(domain):
        return jsonify({
            "error": {"code": "InvalidDomain", "message": "Invalid domain provided"}
        }), 400
    
    # Remove any subdomain prefixes - we want the base domain
    # Simple heuristic: if more than 2 parts, assume first is subdomain
    parts = domain.split(".")
    if len(parts) > 2 and parts[0] in COMMON_SUBDOMAINS:
        domain = ".".join(parts[1:])
    
    found_subdomains = []
    checked = 0
    
    def check_subdomain(subdomain):
        """Check if a subdomain exists."""
        full_domain = f"{subdomain}.{domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # Try A record first
            try:
                answers = resolver.resolve(full_domain, "A")
                ips = [rr.to_text() for rr in answers]
                return {
                    "subdomain": subdomain,
                    "full_domain": full_domain,
                    "found": True,
                    "type": "A",
                    "records": ips,
                    "ttl": answers.rrset.ttl if answers.rrset else None
                }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Try CNAME
            try:
                answers = resolver.resolve(full_domain, "CNAME")
                cnames = [rr.to_text() for rr in answers]
                return {
                    "subdomain": subdomain,
                    "full_domain": full_domain,
                    "found": True,
                    "type": "CNAME",
                    "records": cnames,
                    "ttl": answers.rrset.ttl if answers.rrset else None
                }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Try AAAA (IPv6)
            try:
                answers = resolver.resolve(full_domain, "AAAA")
                ips = [rr.to_text() for rr in answers]
                return {
                    "subdomain": subdomain,
                    "full_domain": full_domain,
                    "found": True,
                    "type": "AAAA",
                    "records": ips,
                    "ttl": answers.rrset.ttl if answers.rrset else None
                }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
                
        except Exception:
            pass
        
        return None
    
    # Use thread pool for parallel lookups
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in COMMON_SUBDOMAINS}
        
        for future in as_completed(futures):
            checked += 1
            result = future.result()
            if result:
                found_subdomains.append(result)
    
    # Sort by subdomain name
    found_subdomains.sort(key=lambda x: x["subdomain"])
    
    # Categorize findings
    categories = {
        "web": ["www", "www2", "www3", "portal", "app", "apps", "mobile", "m", "static", "cdn", "assets"],
        "mail": ["mail", "smtp", "pop", "imap", "webmail", "exchange", "owa", "mx"],
        "dns": ["ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2"],
        "dev": ["dev", "development", "staging", "stage", "test", "testing", "beta", "alpha", "demo", "sandbox", "uat", "qa"],
        "infrastructure": ["vpn", "gateway", "router", "firewall", "proxy", "remote", "rdp", "ssh", "sftp"],
        "database": ["db", "database", "mysql", "mssql", "postgres", "mongodb", "redis"],
        "monitoring": ["monitor", "monitoring", "status", "nagios", "zabbix", "grafana", "prometheus", "kibana"],
        "devops": ["jenkins", "gitlab", "github", "bitbucket", "docker", "kubernetes", "k8s", "git", "repo"],
        "security": ["auth", "login", "sso", "ldap", "secure", "security", "ssl"]
    }
    
    categorized = {}
    for sub in found_subdomains:
        found_cat = "other"
        for cat, subs in categories.items():
            if sub["subdomain"] in subs:
                found_cat = cat
                break
        if found_cat not in categorized:
            categorized[found_cat] = []
        categorized[found_cat].append(sub)
    
    return jsonify({
        "domain": domain,
        "total_checked": checked,
        "total_found": len(found_subdomains),
        "subdomains": found_subdomains,
        "by_category": categorized,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    })


@app.route("/api/dns-diff")
@limiter.limit("20 per minute")
def api_dns_diff():
    """Compare DNS records between two domains or same domain at different servers.
    
    Can be used to:
    - Compare two different domains
    - Compare same domain across different DNS resolvers
    - Verify DNS migration/changes
    """
    domain1 = request.args.get("domain1", "").strip().lower()
    domain2 = request.args.get("domain2", "").strip().lower()
    record_type = request.args.get("type", "A").upper()
    
    # If domain2 is empty, compare domain1 across multiple DNS servers
    compare_servers = not domain2 or domain2 == domain1
    
    if not domain1 or not is_valid_domain_input(domain1):
        return jsonify({
            "error": {"code": "InvalidDomain", "message": "Invalid domain1 provided"}
        }), 400
    
    if domain2 and not compare_servers and not is_valid_domain_input(domain2):
        return jsonify({
            "error": {"code": "InvalidDomain", "message": "Invalid domain2 provided"}
        }), 400
    
    valid_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]
    if record_type not in valid_types:
        return jsonify({
            "error": {"code": "InvalidType", "message": f"Type must be one of: {', '.join(valid_types)}"}
        }), 400
    
    def get_records(domain, server=None):
        """Get DNS records for a domain, optionally from specific server."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            if server:
                resolver.nameservers = [server]
            
            answers = resolver.resolve(domain, record_type)
            records = []
            
            for rr in answers:
                if record_type == "MX":
                    records.append(f"{rr.preference} {rr.exchange.to_text()}")
                elif record_type == "SOA":
                    records.append({
                        "mname": rr.mname.to_text(),
                        "rname": rr.rname.to_text(),
                        "serial": rr.serial,
                        "refresh": rr.refresh,
                        "retry": rr.retry,
                        "expire": rr.expire,
                        "minimum": rr.minimum
                    })
                else:
                    records.append(rr.to_text())
            
            return {
                "success": True,
                "records": sorted(records) if record_type != "SOA" else records,
                "ttl": answers.rrset.ttl if answers.rrset else None,
                "count": len(records)
            }
        except dns.resolver.NXDOMAIN:
            return {"success": False, "error": "Domain not found", "records": []}
        except dns.resolver.NoAnswer:
            return {"success": False, "error": f"No {record_type} records", "records": []}
        except dns.resolver.Timeout:
            return {"success": False, "error": "Query timeout", "records": []}
        except Exception as e:
            return {"success": False, "error": str(e), "records": []}
    
    if compare_servers:
        # Compare same domain across different DNS servers
        servers_to_check = {
            "Google (8.8.8.8)": "8.8.8.8",
            "Cloudflare (1.1.1.1)": "1.1.1.1",
            "Quad9 (9.9.9.9)": "9.9.9.9",
            "OpenDNS (208.67.222.222)": "208.67.222.222"
        }
        
        results = {}
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(get_records, domain1, ip): name 
                      for name, ip in servers_to_check.items()}
            
            for future in as_completed(futures):
                server_name = futures[future]
                results[server_name] = future.result()
        
        # Check if all results match
        record_sets = [frozenset(r["records"]) for r in results.values() if r["success"]]
        all_match = len(set(record_sets)) <= 1 if record_sets else False
        
        # Find differences
        differences = []
        if not all_match and len(record_sets) > 1:
            all_records = set()
            for r in results.values():
                if r["success"]:
                    all_records.update(r["records"])
            
            for record in all_records:
                servers_with = [name for name, r in results.items() 
                               if r["success"] and record in r["records"]]
                servers_without = [name for name, r in results.items() 
                                  if r["success"] and record not in r["records"]]
                if servers_without:
                    differences.append({
                        "record": record,
                        "present_in": servers_with,
                        "missing_from": servers_without
                    })
        
        return jsonify({
            "mode": "server_comparison",
            "domain": domain1,
            "record_type": record_type,
            "servers": results,
            "all_match": all_match,
            "differences": differences
        })
    else:
        # Compare two different domains
        result1 = get_records(domain1)
        result2 = get_records(domain2)
        
        # Analyze differences
        set1 = set(result1["records"]) if result1["success"] else set()
        set2 = set(result2["records"]) if result2["success"] else set()
        
        only_in_1 = list(set1 - set2)
        only_in_2 = list(set2 - set1)
        common = list(set1 & set2)
        
        return jsonify({
            "mode": "domain_comparison",
            "domain1": {
                "name": domain1,
                **result1
            },
            "domain2": {
                "name": domain2,
                **result2
            },
            "record_type": record_type,
            "comparison": {
                "only_in_domain1": only_in_1,
                "only_in_domain2": only_in_2,
                "common": common,
                "match": set1 == set2
            }
        })


@app.route("/api/zone-info")
@limiter.limit("30 per minute")
def api_zone_info():
    """Get comprehensive zone information for a domain.
    
    Provides a complete overview of all DNS records for a domain,
    including NS, SOA, A, AAAA, MX, TXT, CNAME, CAA, and more.
    """
    domain = request.args.get("domain", "").strip().lower()
    
    if not domain or not is_valid_domain_input(domain):
        return jsonify({
            "error": {"code": "InvalidDomain", "message": "Invalid domain provided"}
        }), 400
    
    record_types = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA", "CNAME", "SRV", "DNSKEY", "DS"]
    
    def query_type(rtype):
        """Query a specific record type."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(domain, rtype)
            records = []
            
            for rr in answers:
                if rtype == "MX":
                    records.append({
                        "priority": rr.preference,
                        "host": rr.exchange.to_text()
                    })
                elif rtype == "SOA":
                    records.append({
                        "mname": rr.mname.to_text(),
                        "rname": rr.rname.to_text(),
                        "serial": rr.serial,
                        "refresh": rr.refresh,
                        "retry": rr.retry,
                        "expire": rr.expire,
                        "minimum": rr.minimum
                    })
                elif rtype == "SRV":
                    records.append({
                        "priority": rr.priority,
                        "weight": rr.weight,
                        "port": rr.port,
                        "target": rr.target.to_text()
                    })
                else:
                    records.append(rr.to_text())
            
            return {
                "type": rtype,
                "found": True,
                "records": records,
                "count": len(records),
                "ttl": answers.rrset.ttl if answers.rrset else None
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            return {
                "type": rtype,
                "found": False,
                "records": [],
                "count": 0
            }
    
    # Query all record types in parallel
    results = {}
    with ThreadPoolExecutor(max_workers=len(record_types)) as executor:
        futures = {executor.submit(query_type, rt): rt for rt in record_types}
        
        for future in as_completed(futures):
            rtype = futures[future]
            results[rtype] = future.result()
    
    # Build summary
    summary = {
        "has_ipv4": results["A"]["found"],
        "has_ipv6": results["AAAA"]["found"],
        "has_mail": results["MX"]["found"],
        "has_dnssec": results.get("DNSKEY", {}).get("found", False) or results.get("DS", {}).get("found", False),
        "has_caa": results["CAA"]["found"],
        "nameserver_count": results["NS"]["count"],
        "txt_record_count": results["TXT"]["count"]
    }
    
    # Check for common services in TXT records
    services_detected = []
    if results["TXT"]["found"]:
        txt_records = " ".join(str(r) for r in results["TXT"]["records"])
        
        service_indicators = {
            "Google Workspace": ["google-site-verification", "_spf.google.com"],
            "Microsoft 365": ["MS=", "include:spf.protection.outlook.com"],
            "Mailchimp": ["mailchimp"],
            "SendGrid": ["sendgrid"],
            "Mailgun": ["mailgun"],
            "AWS SES": ["amazonses"],
            "Zendesk": ["zendesk"],
            "Salesforce": ["salesforce"],
            "HubSpot": ["hubspot"],
            "Atlassian": ["atlassian-domain-verification"],
            "Facebook": ["facebook-domain-verification"],
            "Adobe": ["adobe-sign-verification"],
            "DocuSign": ["docusign"],
            "Zoho": ["zoho-verification", "include:zoho"],
            "Fastmail": ["fastmail"]
        }
        
        for service, indicators in service_indicators.items():
            for indicator in indicators:
                if indicator.lower() in txt_records.lower():
                    services_detected.append(service)
                    break
    
    return jsonify({
        "domain": domain,
        "records": results,
        "summary": summary,
        "services_detected": list(set(services_detected)),
        "query_time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    })


@app.errorhandler(404)
def not_found(e):
    """Custom 404 handler."""
    if request.path.startswith("/api/"):
        return jsonify({"error": {"code": "NotFound", "message": "Endpoint not found"}}), 404
    return render_template("404.html"), 404


@app.errorhandler(429)
def rate_limited(e):
    """Handle rate limit exceeded."""
    return jsonify({
        "error": {
            "code": "RateLimited",
            "message": "Too many requests. Please slow down."
        }
    }), 429


@app.errorhandler(500)
def server_error(e):
    """Handle internal server errors."""
    logging.exception("Internal server error")
    if request.path.startswith("/api/"):
        return jsonify({"error": {"code": "ServerError", "message": "Internal server error"}}), 500
    return render_template("404.html"), 500


if __name__ == "__main__":
    # Development-only server; production should use gunicorn
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
