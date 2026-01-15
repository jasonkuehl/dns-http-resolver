# Security Policy

## Supported Versions

Security updates are provided for the **latest released version** of this project. Older versions are not actively supported.

| Version | Supported |
|--------|-----------|
| Latest release | ✅ |
| Older releases | ❌ |

Users are strongly encouraged to run the most recent version to receive security fixes and improvements.

---

## Reporting a Vulnerability

If you discover a security vulnerability, **please do not open a public GitHub issue**.

Instead, report it responsibly using **one of the following methods**:

### Preferred Method
- Email jason@jasonkuehl.com  
- https://github.com/jasonkuehl/dns-http-resolver/security/advisories/new

---

## What to Include in a Report

Please include as much detail as possible:

- Description of the vulnerability
- Steps to reproduce
- Affected versions or configurations
- Potential impact (e.g., DoS, data exposure, SSRF)
- Proof-of-concept code or logs (if available)

---

## Response Timeline

- **Acknowledgement:** within 72 hours
- **Initial assessment:** within 7 days
- **Fix or mitigation:** as soon as reasonably possible, based on severity

You will be kept informed until the issue is resolved or declined.

---

## Disclosure Policy

- Confirmed vulnerabilities will be fixed prior to public disclosure when possible
- Credit will be given unless anonymity is requested
- Coordinated disclosure is encouraged

---

## Security Scope Notes

This project:
- Resolves DNS queries over HTTP
- Is typically deployed in containerized or internal network environments
- Assumes deployment behind appropriate network controls (firewalls, ACLs, etc.)

Issues caused by insecure deployment, misconfiguration, or third-party dependencies may fall outside the direct scope of this project but will be reviewed in good faith.

---
Responsible security disclosures help improve this project for everyone.  
Thank you for helping keep **dns-http-resolver** secure and reliable.
