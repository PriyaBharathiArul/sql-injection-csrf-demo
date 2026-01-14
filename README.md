# Web Security Demo: SQL Injection & CSRF

A hands-on educational platform demonstrating SQL Injection and CSRF vulnerabilities with their mitigations. Built with Flask and Docker for reproducible security testing.

## Features

- **Dual-Mode Architecture**: Run the same codebase in vulnerable or secure mode
- **8+ SQL Injection Attack Vectors**: Authentication bypass, UNION attacks, blind SQLi, second-order injection, and more
- **CSRF Demonstrations**: Interactive attacker site showing real-world CSRF attacks
- **Automated Testing**: Selenium and Python scripts for attack automation
- **Docker Containerized**: Fully isolated environment for safe testing

## 🎥 Project Demo
▶️ [[Watch the demo video (MP4)](https://github.com/PriyaBharathiArul/sql-injection-csrf-demo/releases)]

## Quick Start

```bash
# Start all services (vulnerable app, patched app, attacker site)
./start_demo.sh

# Access the applications
# Vulnerable: http://localhost:5000
# Patched:    http://localhost:5001
# Attacker:   http://localhost:8080
```

**Test Accounts**: `alice/password123`, `bob/secret456`, `charlie/pass789`

## Project Structure

```
├── app/                     # Flask application
│   ├── vuln_sql.py         # Vulnerable SQL injection endpoints
│   ├── patched_sql.py      # Secure endpoints with parameterized queries
│   ├── vuln_csrf.py        # Vulnerable CSRF endpoints
│   ├── patched_csrf.py     # Secure endpoints with token validation
│   └── app.py              # Main application (mode-aware)
├── attacker/               # Simulated attacker website for CSRF demos
├── scripts/                # Attack testing scripts
├── tests/                  # Selenium tests and metrics collection
└── docker-compose.yml      # Service orchestration
```

## SQL Injection Attack Demos

Run automated attacks against both modes:

```bash
# Curl-based attack script (7 vectors)
./attacks/sqli_curl.sh http://localhost:5000 http://localhost:5001

# Advanced Python testing (9+ vectors)
python3 scripts/test_advanced_sqli.py http://localhost:5000 http://localhost:5001

# Blind SQLi password extraction
python3 scripts/blind_sqli_extractor.py http://localhost:5000
```

**Attack Vectors Demonstrated**:
- Authentication bypass (`' OR '1'='1`)
- UNION-based data exfiltration
- UPDATE injection
- Stacked queries (table drops)
- Second-order SQL injection
- Boolean-based blind SQLi
- Time-based blind SQLi
- Error-based information extraction

## CSRF Attack Demos

```bash
# 1. Login to vulnerable app at http://localhost:5000
# 2. Open attacker site at http://localhost:8080
# 3. Click attack buttons to trigger CSRF

# Or use Selenium automation
python3 tests/csrf_selenium.py
```

## Security Mitigations Implemented

**SQL Injection Prevention**:
- Parameterized queries with placeholders (`?`)
- Input validation and sanitization
- Error message suppression
- Safe SQL API usage (`execute()` vs `executescript()`)

**CSRF Prevention**:
- Cryptographically secure CSRF tokens
- Constant-time token comparison
- Origin/Referer header validation
- SameSite cookie attributes
- Content Security Policy headers

## Architecture

The application runs in two modes controlled by the `MODE` environment variable:

- `MODE=vulnerable` (port 5000) - Intentionally insecure for demonstration
- `MODE=patched` (port 5001) - Implements all security best practices

This dual-mode design allows side-by-side comparison using the same codebase.

## Requirements

- Docker & Docker Compose
- Python 3.11+ (for standalone scripts)
- curl (for attack scripts)

## Documentation

- [Advanced SQL Injection Techniques](docs/ADVANCED_SQLI.md) - Deep dive into exploitation methods
- Comprehensive inline code comments explaining vulnerabilities and fixes

## ⚠️ Educational Use Only

This project contains intentionally vulnerable code for educational purposes. **Never deploy to production or public networks.** Use only in isolated environments for learning security concepts.

## License

MIT License - Educational use only

## Authors

Vasavi Udupa & Priya Bharathi Arul

---

**Inspired by**: [SEED Security Labs](https://seedsecuritylabs.org/Labs_20.04/Web/)
