
# 🕵️‍♂️ Advanced Vulnerability Scanner (CLI Tool)

A high-performance, developer-focused security scanner for finding XSS, SQLi, CSRF, IDOR, and more.

## 🚀 Quick Start (Windows)

1. **Install Python 3.10+**: [Download Here](https://www.python.org/downloads/)
2. **Setup Dependencies**:
   Open a terminal in this folder and run:
   ```cmd
   pip install -r requirements.txt
   ```
3. **Run a Scan**:
   You can simply double-click **`run_scan.bat`**, or run manually:
   ```cmd
   python scanner.py -u https://example.com
   ```

---

## 🛠️ Usage Options

| Argument | Description | Example |
| :--- | :--- | :--- |
| `-u` | Target URL to scan (Required) | `-u http://testphp.vulnweb.com` |
| `-t` | Number of concurrent threads (Default: 10) | `-t 20` |
| `-o` | Output JSON file path | `-o report.json` |

### 🔐 Authenticated Scanning

To scan behind a login page:

```cmd
python scanner.py -u http://site.com/dashboard --auth-user "admin" --auth-pass "12345" --login-url http://site.com/login
```

## 📊 Output
The tool generates a **JSON Report** containing:
- **Vulnerability Details**: Type, Severity, Evidence
- **PoC**: Replay request/response
- **Risk Score**: Calculated security grade (A-F)

---
*Generated for Client Release*
