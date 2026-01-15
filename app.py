# New app.py with improved logging and DNSSEC clarity

import os
import time
import logging
import re
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import dns.flags
import dns.exception
import ipaddress
from flask import Flask, jsonify, request, render_template
from dotenv import load_dotenv
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from concurrent.futures import ThreadPoolExecutor, as_completed

load_dotenv()

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

if LIMITER_STORAGE:
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200 per minute"],
        storage_uri=LIMITER_STORAGE
    )
    limiter.init_app(app)
else:
    # fallback for local/dev (will produce in-memory warning in logs)
    limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per minute"])

# DNS servers to query (comma‑separated in ENV). If empty, use system resolver (configure=True).
DNS_SERVERS = [s.strip() for s in os.environ.get("DNS_SERVERS", "").split(",") if s.strip()]
USE_SYSTEM_RESOLVER = len(DNS_SERVERS) == 0

# Old strict regex removed; use a permissive validator that accepts IPs, single-label hostnames, and FQDNs.
def is_valid_domain_input(s: str) -> bool:
    if not s:
        return False
    s = s.strip()
    if len(s) > 253 or " " in s:
        return False
    # allow raw IPs
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        pass
    # remove trailing dot if present
    if s.endswith("."):
        s = s[:-1]
    labels = s.split(".")
    for label in labels:
        if not (1 <= len(label) <= 63):
            return False
        if not re.match(r"^[A-Za-z0-9-]+$", label):
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
    return True

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/resolve")
def resolve_page():
    return render_template("resolve.html")

@app.route("/trace")
def trace_page():
    return render_template("trace.html")

@app.route("/readme")
def readme_page():
    return render_template("readme.html")

@app.route("/api/resolve")
@limiter.limit("60/minute")
def api_resolve():
    domain = request.args.get("domain", "").strip().lower()
    rtype = request.args.get("type", "A").upper()
    if not domain:
        return jsonify({"error": {"code": "BadRequest", "message": "No domain specified"}}), 400
    if not is_valid_domain_input(domain):
        return jsonify({"error": {"code": "BadRequest", "message": "Invalid domain format"}}), 400

    logging.info("Resolve requested: domain=%s type=%s from=%s", domain, rtype, request.remote_addr)

    ALLOWED = {"A","AAAA","MX","NS","CNAME","TXT","SOA","PTR","SRV","ALL"}
    if rtype not in ALLOWED:
        return jsonify({"error": {"code": "BadRequest", "message": f"Invalid type: {rtype}"}}), 400

    types = ["A","AAAA","MX","NS","CNAME","TXT","SOA","PTR","SRV"] if rtype == "ALL" else [rtype]

    def query_server(server, t):
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
        # Use system resolver when server is falsy (fallback) or when configured to use system resolver
        try:
            if USE_SYSTEM_RESOLVER or not server:
                resolver = dns.resolver.Resolver()  # configure=True reads /etc/resolv.conf
            else:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [server]
            # disable caching to honor "no caching" requirement
            resolver.cache = None
            resolver.timeout = 3
            resolver.lifetime = 3

            start = time.time()
            answer = resolver.resolve(domain, t, raise_on_no_answer=False)
            entry["latency_ms"] = round((time.time() - start) * 1000, 2)

            if answer.rrset is not None:
                entry["answers"] = [rr.to_text() for rr in answer]
                entry["ttl_remaining"] = answer.rrset.ttl or 0

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
        with ThreadPoolExecutor(max_workers=min(16, max(1, len(DNS_SERVERS) * len(types)))) as ex:
            futures = []
            if USE_SYSTEM_RESOLVER:
                for t in types:
                    futures.append(ex.submit(query_server, None, t))
            else:
                for t in types:
                    for server in DNS_SERVERS:
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

def dns_trace(domain):
    trace_steps = []
    ROOT_SERVERS = [
        "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
        "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
        "192.36.148.17", "192.58.128.30", "193.0.14.129",
        "199.7.83.42", "202.12.27.33"
    ]
    servers_to_try = ROOT_SERVERS.copy()
    visited = set()

    step_count = 1
    while servers_to_try:
        server = servers_to_try.pop(0)
        if server in visited:
            continue
        visited.add(server)
        step = {
            "step": step_count,
            "server": server,
            "response_code": None,
            "answer": [],
            "authority": [],
            "additional": []
        }
        try:
            q = dns.message.make_query(domain, dns.rdatatype.ANY, use_edns=True)
            r = dns.query.udp(q, server, timeout=3)
            step["response_code"] = dns.rcode.to_text(r.rcode())
            for rrset in r.answer:
                for rr in rrset:
                    step["answer"].append(rr.to_text())
            for rrset in r.authority:
                for rr in rrset:
                    step["authority"].append(rr.to_text())
            for rrset in r.additional:
                for rr in rrset:
                    step["additional"].append(rr.to_text())
            trace_steps.append(step)
            next_ip = None
            for rr in r.additional:
                if rr.rdtype == dns.rdatatype.A:
                    next_ip = rr[0].to_text()
                    break
            if next_ip:
                servers_to_try.append(next_ip)
            step_count += 1
        except Exception as e:
            logging.warning(f"Trace stopped at step {step_count}: {e}")
            break
    return trace_steps

@app.route("/favicon.ico")
def favicon():
    return "", 204

if __name__ == "__main__":
    # Development-only server; production should use gunicorn
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
