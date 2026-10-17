# EXENOM — External Attack Surface Management

<div align="center">

```
  _______  __   __  _______  _   _    ___    __  __
 |  ____|  \ \ / / |__   __|| \ | |  / _ \  |  \/  |
 | |__      \ V /     | |  |  \| | | | | | | \  / |
 |  __|     / _ \     | |  | . ' | | |_| | | |\/| |
 |_____|   /_/ \_\    |_|  |_| \_|  \___/  |_|  |_|
```

**An advanced attack-surface reconnaissance & red-team tool with 30 modules and 330+ encoded WAF-bypass payloads per category.**

Built by **Rudresha RK** — Cybersecurity Undergraduate

[Features](#-features) · [Quick Start](#-quick-start) · [Modules](#-modules) · [Usage](#-usage) · [Deploy](#-deployment) · [Python CLI](#-standalone-python-cli)

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Modules](#-modules)
- [Usage](#-usage)
- [Standalone Python CLI](#-standalone-python-cli)
- [Deployment](#-deployment)
- [Configuration](#-configuration)
- [Disclaimer](#-disclaimer)
- [License](#-license)

---

## Overview

EXENOM is a comprehensive External Attack Surface Management (EASM) tool that maps an organization's internet-facing assets from a single target. It combines 30 reconnaissance and red-team modules into a single tool with both a **web terminal UI** and a **real CLI**.

### Two ways to run:

| Interface | Description | Best for |
|-----------|-------------|----------|
| **Web Terminal** | Browser-based xterm.js terminal with live streaming output | Interactive use, demos |
| **Real CLI** | `bun run easm scan <target>` or `python3 easm.py scan <target>` | Automation, scripts, CI/CD |

---

## 🚀 Features

- **30 recon & red-team modules** covering DNS, subdomains, ports, HTTP, TLS, vulnerabilities, cloud assets, WAF bypass, injection, and more
- **330+ encoded WAF-bypass payloads per category** (XSS, SQLi, LFI, CMDi, Open Dirs) using layered encoding (URL/HTML/Unicode/hex/case/whitespace)
- **Multi-key API rotation** for Shodan, VirusTotal, c99, SecurityTrails — automatically falls back to the next key on rate limits
- **6 passive subdomain sources** (crt.sh, HackerTarget, AlienVault OTX, Anubis, RapidDNS, brute-force)
- **Cloud asset discovery** (AWS S3, GCP, Azure, GitHub)
- **Real terminal output** — colored ANSI tables, severity-tagged findings, live streaming
- **Zero-dependency Python CLI** — runs anywhere with Python 3.7+

---

## ⚡ Quick Start

### Option A: Web Terminal (Next.js)

```bash
# Clone the repo
git clone https://github.com/yourusername/exenom.git
cd exenom

# Install dependencies
bun install

# Start the scan engine (port 3004)
bun run easm-service

# In another terminal, start the web app (port 3000)
bun run dev

# Open http://localhost:3000 in your browser
```

### Option B: Real CLI (Bun)

```bash
# Clone & install
git clone https://github.com/yourusername/exenom.git
cd exenom
bun install

# Scan any target
bun run easm scan example.com
bun run easm scan example.com --modules dns,http,vulns,firewall
bun run easm scan example.com --output json > report.json
```

### Option C: Standalone Python (zero dependencies)

```bash
# Download just the Python file
curl -O https://raw.githubusercontent.com/yourusername/exenom/main/download/easm.py

# Run it — no pip install needed!
python3 easm.py scan example.com
python3 easm.py scan example.com --modules dns,http,vulns,firewall
python3 easm.py scan example.com --output json > report.json
```

---

## 📦 Modules

EXENOM has **30 modules** covering the full attack-surface lifecycle:

### Reconnaissance
| Module | Description |
|--------|-------------|
| `dns` | DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA) |
| `subdomains` | Subdomain enumeration (6 passive sources + brute-force) |
| `ports` | TCP + UDP port scan with banner grabbing + OS fingerprint |
| `recon` | WHOIS (RDAP), ASN, GeoIP, reverse DNS |
| `wayback` | Wayback Machine historical URLs, deleted pages, file types |

### Web Application Security
| Module | Description |
|--------|-------------|
| `http` | HTTP/HTTPS probing (status, title, server, redirect) |
| `tls` | TLS certificate analysis (issuer, expiry, SAN, self-signed) |
| `tech` | Technology fingerprinting (25+ signatures) |
| `banners` | Service banner grabbing (FTP/SSH/SMTP/Redis) |
| `screenshots` | Deep HTTP fingerprint (favicon hash, redirect chain, cookies, security headers) |
| `ssltests` | Advanced SSL/TLS tests (protocols, ciphers, POODLE/BEAST) |

### Vulnerability & Misconfiguration
| Module | Description |
|--------|-------------|
| `vulns` | Security headers + 35 exposed-path checks + CORS + .git dump |
| `opendirs` | Open directory listings + 66 sensitive file probes |
| `emailsec` | SPF / DMARC / DKIM / MX validation |
| `firewall` | WAF detection (16 signatures) + 330+ bypass payloads per category |
| `subtakeover` | Subdomain takeover detection (23-service fingerprint DB) |

### Cloud & Infrastructure
| Module | Description |
|--------|-------------|
| `cloudenum` | Cloud asset enum (AWS S3, GCP, Azure, GitHub) |
| `threatintel` | 4 threat-intel APIs (Shodan, c99, VirusTotal, SecurityTrails) with multi-key rotation |

### Advanced Red-Team
| Module | Description |
|--------|-------------|
| `jsanalyze` | JavaScript analysis (14 secret types, endpoints, cloud keys, internal URLs) |
| `api` | API discovery (endpoints, GraphQL introspection, Swagger/OpenAPI, versioned APIs) |
| `inject` | Injection testing (SQLi, NoSQLi, SSTI, CMDi, XSS, LDAP, XPath, open redirect) |
| `webdav` | WebDAV probing (PROPFIND, MKCOL, PUT file upload) |
| `crawl` | Web crawler (internal/external links, emails, phones, files) |
| `spider` | Advanced spider (forms, hidden inputs, comments, meta tags, structured data) |

### Attack Vectors
| Module | Description |
|--------|-------------|
| `hostheader` | Host header injection + SSRF test points + CRLF injection |
| `auth` | Auth bypass (default creds, JWT none-alg, weak secret, session fixation) |
| `csrf` | CSRF token validation + SameSite cookie audit |
| `deserialization` | Deserialization (PHP/Java/Python pickle/YAML/Fastjson) |
| `smuggling` | HTTP request smuggling (CL.TE / TE.CL / TE.TE / CL.CL) |
| `cache` | Cache poisoning (unkeyed headers) + web cache deception |

---

## 📖 Usage

### Web Terminal Commands

Type these directly into the terminal in your browser:

```
scan example.com                                    # full scan (all 30 modules)
scan example.com --modules dns,http,vulns,firewall  # selected modules only
scan example.com --ports 80,443,8000-8100           # custom ports
scan example.com --no-subdomains                    # skip subdomain enum (faster)
targets example.com,github.com,google.com           # scan multiple targets
modules                                             # list all modules
about                                               # tool info + developer
help                                                # show all commands
clear                                               # clear screen
```

### CLI Commands

```bash
# Full scan
bun run easm scan example.com

# Selected modules
bun run easm scan example.com --modules dns,http,vulns,firewall

# Custom ports with ranges
bun run easm scan example.com --ports 80,443,8000-8100

# Skip subdomain enumeration (faster)
bun run easm scan example.com --no-subdomains

# JSON report output
bun run easm scan example.com --output json > report.json

# Tuning
bun run easm scan example.com --timeout 6000 --concurrency 100
```

### Quick Module Combos

| Goal | Command |
|------|---------|
| **Recon** | `scan example.com --modules dns,subdomains,recon,threatintel` |
| **Web app sec** | `scan example.com --modules http,vulns,firewall,inject,spider` |
| **Cloud** | `scan example.com --modules cloudenum,subtakeover,jsanalyze` |
| **Red-team** | `scan example.com --modules auth,csrf,deserialization,smuggling,cache` |
| **Full** | `scan example.com` |

---

## 🐍 Standalone Python CLI

The Python edition (`download/easm.py`) is a **single file, zero-dependency** script that runs anywhere with Python 3.7+. No `pip install` needed.

```bash
# Download
curl -O https://raw.githubusercontent.com/yourusername/exenom/main/download/easm.py

# Full scan
python3 easm.py scan example.com

# Selected modules
python3 easm.py scan example.com --modules dns,http,vulns,firewall

# JSON report
python3 easm.py scan example.com --output json > report.json

# All flags
python3 easm.py scan example.com --ports 80,443,8080 --no-subdomains --timeout 6000 --concurrency 100
```

### Python modules (10)
`dns` · `subdomains` · `ports` · `http` · `tls` · `tech` · `vulns` · `emailsec` · `firewall` · `cloudenum`

---

## 🚢 Deployment

See **[DEPLOY.md](DEPLOY.md)** for detailed deployment instructions:

- **Vercel** (free, recommended for Next.js) — 1-click deploy
- **Docker** — `docker-compose up` and you're running
- **Self-host** — any VPS with Node.js/Bun
- **Python CLI** — download `easm.py` and run (no install needed)

---

## ⚙️ Configuration

### API Keys (optional)

The threat-intel module uses 4 APIs. Keys are pre-configured but you can override them via environment variables:

```bash
# Multi-key (comma-separated) — the tool rotates through all keys
export EASM_SHODAN_KEYS="key1,key2"
export EASM_C99_KEYS="key1,key2,key3"
export EASM_VIRUSTOTAL_KEYS="key1,key2"
export EASM_SECURITYTRAILS_KEYS="key1"
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `EASM_SHODAN_KEYS` | Shodan API keys (comma-separated) | Pre-configured |
| `EASM_C99_KEYS` | c99 API keys (comma-separated) | Pre-configured |
| `EASM_VIRUSTOTAL_KEYS` | VirusTotal API keys (comma-separated) | Pre-configured |
| `EASM_SECURITYTRAILS_KEYS` | SecurityTrails API keys (comma-separated) | Pre-configured |

---

## 📊 WAF-Bypass Payload Database

The `firewall` module generates **330+ encoded payloads per category** (1,320+ total) using layered encoding:

| Category | Payloads | Encoding layers |
|----------|----------|-----------------|
| **XSS** | 330 | URL (1x/2x/3x), HTML entity (dec/hex), Unicode, hex, mixed-case, whitespace |
| **SQLi** | 330 | + SQL inline comments, versioned comments |
| **LFI** | 330 | + dot-slash duplication, php:// wrappers |
| **CMDi** | 330 | + $IFS substitution, backtick/$() syntax |
| **Open Dirs** | 330 | + path encoding variants |

Per-WAF curated sets: Cloudflare, ModSecurity/OWASP CRS, AWS WAF, Akamai, Imperva Incapsula.

---

## ⚠️ Disclaimer

This tool is for **authorized security testing and educational purposes only**. Always obtain explicit permission before scanning any target you do not own. The authors are not responsible for misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE).

---

## 👨‍💻 Developer

**Built by Rudresha RK**
Cybersecurity Undergraduate

---

<div align="center">

**⭐ If this tool helped you, give it a star on GitHub! ⭐**

</div>
