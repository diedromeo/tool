# Advanced Vulnerability Scanner CLI - Documentation

## 1. Introduction
The **Advanced Vulnerability Scanner CLI** is a high-performance, multithreaded security auditing tool designed for automated vulnerability assessment. It operates independently of any web framework and provides real-time feedback with color-coded severity levels.

### Key Features
*   **High Speed**: Multithreaded architecture for concurrent crawling and scanning.
*   **Real-Time Output**: Instant feedback on the console as vulnerabilities are found.
*   **Comprehensive Reporting**: Generates detailed JSON reports compliant with dashboard integrations.
*   **Authentication Support**: Full support for scanning behind login pages using Form-based authentication.
*   **PoC Generation**: Automatically constructs Proof-of-Concept URLs for detected vulnerabilities.
*   **Sensitive File Discovery**: Automatically checks for critical exposures including:
    *   `.env`, `config.php`, `wp-config.php` (Credentials)
    *   `.git/HEAD`, `.git/config` (Source Code Exposure)
    *   `backup.zip`, `backup.sql` (Database Dumps)
    *   `.vscode/settings.json`, `.idea/workspace.xml` (IDE Metadata)
    *   `phpinfo.php`, `.htaccess`, `web.config` (Server Configuration)

### Supported Vulnerabilities
The scanner is capable of detecting a wide range of web application vulnerabilities, including but not limited to:

*   **Injection Attacks**:
    *   **SQL Injection (SQLi)**: Classic, Error-based, and Boolean-based detection.
    *   **Cross-Site Scripting (XSS)**: Reflected, Stored, and DOM-based XSS verification.
    *   **Command Injection**: OS command execution flaws.
    *   **SSTI**: Server-Side Template Injection.

*   **Broken Authentication**:
    *   **Weak Credentials**: Brute-force protection testing (Rate limiting checks).
    *   **Session Fixation**: Checks if session IDs change upon login.
    *   **Cookie Security**: Missing `HttpOnly` and `Secure` flags.

*   **Security Misconfigurations**:
    *   **CORS**: Cross-Origin Resource Sharing misconfigurations.
    *   **Security Headers**: Missing `Content-Security-Policy`, `X-Frame-Options`, `HSTS`, etc.
    *   **Clickjacking**: Missing frame protection headers.

*   **Information Disclosure**:
    *   Sensitive file exposure (`.env`, `.git`, backups, logs).
    *   Server version leakage (`Server` headers, `phpinfo.php`).

*   **Logical Risks**:
    *   **IDOR**: Insecure Direct Object Reference patterns.
    *   **Open Redirect**: Unvalidated redirects and forwards.
    *   **CSRF**: Cross-Site Request Forgery weaknesses in forms.

---

## 2. Installation

### Prerequisites
*   Python 3.10 or higher
*   `pip` (Python Package Installer)

### Setup
1.  Navigate to the `scanner_cli_release` directory.
2.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

---

## 3. Usage Guide

### Help Command
You can view the full list of options and examples by running:

```bash
python scanner_cli.py -h
```

**Output:**
```text
usage: scanner_cli.py [options] -u <url>

Advanced Web Vulnerability Scanner CLI Tool
-------------------------------------------
A high-performance, multithreaded vulnerability scanner supporting:
- SQL Injection, XSS, SSRF, IDOR, and more.
- Real-time output.
- Authenticated scanning.

options:
  -h, --help            show this help message and exit
  -u, --url URL         Target URL to scan
  -t, --threads THREADS
                        Number of concurrent threads (default: 10)
  -o, --output OUTPUT   Output JSON file path (default:
                        scan_result_<timestamp>.json)

Authentication Options:
  --auth-user AUTH_USER
                        Username for authenticated scan
  --auth-pass AUTH_PASS
                        Password for authenticated scan
  --login-url LOGIN_URL
                        Login URL for authenticated scan
  --config CONFIG       Path to configuration JSON file (contains auth details)

EXAMPLES:

1. Basic Scan (Unauthenticated):
   python scanner_cli.py -u http://testphp.vulnweb.com -t 20

2. Authenticated Scan (Using Config File - RECOMMENDED):
   python scanner_cli.py -u http://testphp.vulnweb.com --config config.json

   Config File Structure (config.json):
   {
       "login_url": "http://testphp.vulnweb.com/login.php",
       "method": "POST",
       "username_field": "uname",
       "password_field": "pass",
       "username": "test",
       "password": "test",
       "success_indicator": "Logout"
   }

3. Authenticated Scan (Using CLI Arguments):
   python scanner_cli.py -u http://testphp.vulnweb.com \
       --auth-user "test" --auth-pass "test" --login-url "http://testphp.vulnweb.com/login.php"

4. Save Report to Custom File:
   python scanner_cli.py -u http://target.com -o myscan.json
```

### Basic Scan (Non-Authenticated)
To perform a standard scan on a public website:

```bash
python scanner_cli.py -u http://example.com
```

### Performance Tuning (Speed)
You can control the scan speed by adjusting the number of concurrent threads.
*   **Default**: 10 threads
*   **Recommended for Speed**: 20-50 threads (depending on server capacity)

**Example (Fast Scan):**
```bash
python scanner_cli.py -u http://example.com -t 50
```

### Saving Results
By default, results are saved to `scan_result_<timestamp>.json`. You can specify a custom filename:

```bash
python scanner_cli.py -u http://example.com -o my_report.json
```

---

## 4. Authenticated Scanning
The scanner can log in to a target application to scan protected pages. You can provide credentials via CLI arguments or a configuration file.

### Method A: Using CLI Arguments
Pass the username, password, and the *exact* login URL directly.

```bash
python scanner_cli.py -u http://example.com/dashboard \
    --auth-user "admin" \
    --auth-pass "password123" \
    --login-url "http://example.com/login"
```

### Method B: Using Configuration File (Recommended)
For complex logins or repeated scans, use a JSON configuration file.

1.  **Create a `config.json` file**:
    ```json
    {
        "login_url": "http://testphp.vulnweb.com/login.php",
        "method": "POST",
        "username_field": "uname",
        "password_field": "pass",
        "username": "test",
        "password": "test",
        "success_indicator": "Logout"
    }
    ```

    *   `login_url`: The URL where the login form is POSTed to.
    *   `method`: HTTP method (usually "POST").
    *   `username_field`: The `name` attribute of the username input field in HTML.
    *   `password_field`: The `name` attribute of the password input field.
    *   `success_indicator`: A string that appears on the page *only* after a successful login (e.g., "Welcome", "Logout", "Dashboard").

2.  **Run with Config**:
    ```bash
    python scanner_cli.py -u http://testphp.vulnweb.com --config config.json
    ```

---

## 5. Output Format (JSON)
The scanner generates a JSON report designed for easy parsing and dashboard integration.

### Structure
```json
{
    "scan_metadata": {
        "target": "http://testphp.vulnweb.com",
        "scan_time": "2026-02-15T21:38:30.123456",
        "duration_seconds": 120.5,
        "threads_used": 20,
        "authenticated": true
    },
    "chart_values": {
        "labels": ["Critical", "High", "Medium", "Low", "Info"],
        "data": [1, 3, 5, 2, 10]
    },
    "severity_summary": {
        "Critical": 1,
        "High": 3,
        "Medium": 5,
        "Low": 2,
        "Info": 10
    },
    "vulnerabilities": [
        {
            "name": "Reflected XSS",
            "severity": "High",
            "endpoint": "http://testphp.vulnweb.com/listproducts.php",
            "parameter": "cat",
            "payload": "<script>alert(1)</script>",
            "evidence": "Payload reflected in response",
            "owasp_reference": "https://owasp.org/www-community/attacks/xss/"
        },
        {
            "name": "Sensitive File Exposure",
            "severity": "High",
            "endpoint": "http://testphp.vulnweb.com/.git/HEAD",
            "parameter": ".git/HEAD",
            "payload": "GET /.git/HEAD",
            "evidence": "Found accessible file '.git/HEAD' with status 200.",
            "owasp_reference": "https://owasp.org/www-community/vulnerabilities/Sensiive_Data_Exposure"
        }
    ]
}
```

### Fields Description
*   **scan_metadata**: Details about the scan execution time and settings.
*   **chart_values**: Pre-formatted arrays for generating charts (e.g., in Chart.js or similar libraries).
*   **severity_summary**: Key-value pairs of vulnerability counts.
*   **vulnerabilities**: List of all found issues.
    *   `owasp_reference`: Link to official OWASP documentation for remediation.
    *   `payload`: The specific attack string used.
    *   `evidence`: Why the scanner flagged this issue.

---

## 6. Troubleshooting

*   **Connection Warnings**: If you see "Connection pool is full", the scanner is automatically handling it, but you might want to slightly reduce threads if the target server is unstable.
*   **Authentication Failed**: Check the `success_indicator` in your `config.json`. Ensure it exactly matches text visible *only* after login.
*   **Missing Dependencies**: Ensure you ran `pip install -r requirements.txt`.
