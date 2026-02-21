
import requests
from scanner_engine.utils import format_http_request, format_http_response

class ClickjackingScanner:
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

    def scan_url(self, url):
        try:
            res = self.session.get(url, timeout=5)
            headers = res.headers
            
            x_frame_options = headers.get('X-Frame-Options', '').upper()
            csp = headers.get('Content-Security-Policy', '').lower()
            
            is_vulnerable = True
            evidence = ""
            
            # Check X-Frame-Options
            if 'DENY' in x_frame_options or 'SAMEORIGIN' in x_frame_options:
                is_vulnerable = False
            else:
                evidence = "Missing or invalid X-Frame-Options header. "

            # Check CSP frame-ancestors (Modern way)
            if 'frame-ancestors' in csp:
                is_vulnerable = False
                evidence = "" # Reset if CSP is present
            else:
                evidence += "Missing frame-ancestors in Content-Security-Policy."

            if is_vulnerable:
                self._add_vulnerability({
                    "name": "Clickjacking (UI Redressing)",
                    "severity": "Low",
                    "endpoint": url,
                    "parameter": "HTTP Headers",
                    "payload": "None (Header Missing)",
                    "evidence": evidence.strip()
                }, response=res)
        except: pass

    def get_results(self):
        return self.vulnerabilities
