
import requests
import logging
from scanner_engine.utils import format_http_request, format_http_response

logger = logging.getLogger(__name__)

COMMON_PATHS = [
    ".env",
    ".git/HEAD",
    ".git/config",
    "robots.txt",
    "sitemap.xml",
    ".htaccess",
    "phpinfo.php",
    "config.php",
    "wp-config.php",
    ".idea/workspace.xml",
    "backup.zip",
    "backup.sql",
    ".vscode/settings.json",
    "composer.json",
    "package.json",
    "server-status",
    "trace.axd",
    "web.config"
]

class InfoDisclosureScanner:
    def __init__(self, session=None, on_vuln=None):
        self.session = session if session else requests.Session()
        self.vulnerabilities = []
        self.on_vuln = on_vuln

    def _add_vulnerability(self, data, response=None):
        if response:
            data['request'] = format_http_request(response.request)
            data['response'] = format_http_response(response)
        self.vulnerabilities.append(data)
        if self.on_vuln:
            self.on_vuln(data)

    def scan_url(self, base_url):
        # Ensure base_url ends with slash for joining
        if not base_url.endswith('/'):
            base_url += '/'
            
        for path in COMMON_PATHS:
            target = base_url + path
            try:
                # Use HEAD/GET depending on expected size, but GET is safer for small files like .env
                res = self.session.get(target, timeout=5, allow_redirects=False)
                
                # Check for 200 OK and potential content match
                if res.status_code == 200:
                    # Filter false positives (e.g. valid HTML pages instead of raw files)
                    if self._is_valid_exposure(path, res):
                         self._add_exposure_vuln(target, path, res)
                         
            except Exception:
                pass

    def _is_valid_exposure(self, path, res):
        content = res.text.lower()
        if path == ".env":
            return "app_key=" in content or "db_password=" in content
        if path == ".git/HEAD":
            return "ref: refs/" in content
        if path == "robots.txt":
            return "user-agent:" in content
        if path == "phpinfo.php":
            return "php version" in content
        
        # General check: If we expected a specific file but got a generic HTML page, ignore
        if "<html" in content and path not in ["robots.txt", "sitemap.xml", "phpinfo.php"]:
            return False
            
        return True

    def _add_exposure_vuln(self, url, path, res):
        severity = "Info"
        if path in [".env", ".git/HEAD", "wp-config.php", "backup.sql"]:
            severity = "High"
        elif path in ["phpinfo.php", ".htaccess"]:
            severity = "Medium"
            
        self._add_vulnerability({
            "name": "Sensitive File Exposure",
            "severity": severity,
            "endpoint": url,
            "parameter": path,
            "payload": f"GET /{path}",
            "evidence": f"Found accessible file '{path}' with status 200. Content snippet: {res.text[:50]}..."
        }, response=res)

    def get_results(self):
        return self.vulnerabilities
