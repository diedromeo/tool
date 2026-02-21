
import requests
from scanner_engine.utils import format_http_request, format_http_response

class HeaderScanner:
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
            
            # 1. HttpOnly Cookies Check
            cookies = res.cookies
            for cookie in cookies:
                # Basic check for HttpOnly attribute
                if not getattr(cookie, 'httponly', False):
                    self._add_vulnerability({
                        "name": "Sensitive Cookie without HttpOnly Flag",
                        "severity": "Medium",
                        "endpoint": url,
                        "parameter": f"Cookie: {cookie.name}",
                        "payload": "Missing HttpOnly",
                        "evidence": f"The cookie '{cookie.name}' is missing the HttpOnly flag, making it accessible to client-side scripts."
                    }, response=res)

            # 2. CSP Presence Check
            csp = headers.get('Content-Security-Policy', '')
            if not csp:
                self._add_vulnerability({
                    "name": "Missing Content Security Policy (CSP)",
                    "severity": "Low",
                    "endpoint": url,
                    "parameter": "HTTP Header",
                    "payload": "None",
                    "evidence": "The response does not include a Content-Security-Policy header, increasing the risk of XSS and data injection."
                }, response=res)
            elif "unsafe-inline" in csp.lower() or "unsafe-eval" in csp.lower():
                self._add_vulnerability({
                    "name": "Weak Content Security Policy (CSP)",
                    "severity": "Low",
                    "endpoint": url,
                    "parameter": "Content-Security-Policy",
                    "payload": csp[:50] + "...",
                    "evidence": "The CSP includes 'unsafe-inline' or 'unsafe-eval', which significantly weakens XSS protections."
                }, response=res)
        except: pass

    def get_results(self):
        return self.vulnerabilities
