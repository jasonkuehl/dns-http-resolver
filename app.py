# New app.py with improved logging and DNSSEC clarity

import os
import time
import logging
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import dns.flags
import dns.exception
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# DNS servers to query (comma‑separated in ENV)
DNS_SERVERS = os.environ.get("DNS_SERVERS", "8.8.8.8,1.1.1.1").split(",")

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
def api_resolve():
    domain = request.args.get("domain", "").strip()
    rtype = request.args.get("type", "A").upper()
    if not domain:
        return jsonify({"error": "No domain specified"}), 400

    ALL_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "PTR", "SRV"]
    types = ALL_TYPES if rtype == "ALL" else [rtype]

    raw_results = []
    for t in types:
        for server in DNS_SERVERS:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [server]
            resolver.timeout = 3
            resolver.lifetime = 3

            entry = {
                "record_type": t,
                "dns_servers": [server],
                "answers": [],
                "authority": [],
                "flags": {},
                "dnssec": None,
                "latency_ms": 0,
                "ttl_remaining": 0,
                "error": None
            }

            start = time.time()
            try:
                answer = resolver.resolve(domain, t, raise_on_no_answer=False)
                entry["latency_ms"] = round((time.time() - start) * 1000, 2)
                min_ttl = None
                answers = []
                if answer.rrset is not None:
                    for rr in answer:
                        answers.append(rr.to_text())
                    min_ttl = answer.rrset.ttl
                entry["answers"] = answers
                entry["ttl_remaining"] = min_ttl if min_ttl else 0
                try:
                    resp = answer.response
                    entry["flags"] = {
                        "aa": bool(resp.flags & dns.flags.AA),
                        "ra": bool(resp.flags & dns.flags.RA),
                        "rd": bool(resp.flags & dns.flags.RD),
                        "ad": bool(resp.flags & dns.flags.AD)
                    }
                    entry["dnssec"] = "validated" if entry["flags"].get("ad") else "unverified"
                except Exception as e:
                    logging.warning(f"DNSSEC parsing failed: {e}")
                    entry["flags"] = {}
                    entry["dnssec"] = "unknown"
                try:
                    auth_list = []
                    for rrset in answer.response.authority:
                        for rr in rrset:
                            auth_list.append(rr.to_text())
                    entry["authority"] = auth_list
                except Exception as e:
                    logging.warning(f"Authority parsing failed: {e}")
                    entry["authority"] = []
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
                logging.error(f"Unexpected error for {domain} type {t} on {server}: {e}")
            raw_results.append(entry)

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
def api_trace():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    try:
        trace_data = dns_trace(domain)
        return jsonify({"domain": domain, "trace": trace_data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
