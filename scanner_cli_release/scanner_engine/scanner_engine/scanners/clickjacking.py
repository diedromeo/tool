
import requests

class ClickjackingScanner:
    def __init__(self, session=None, on_vuln=None):
        self.session = session if session else requests.Session()
        self.vulnerabilities = []
        self.on_vuln = on_vuln

    def _format_request(self, request):
        if not request: return ""
        headers = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
        body = request.body if request.body else ""
        if isinstance(body, bytes):
            try: body = body.decode('utf-8', errors='ignore')
            except: body = "<binary data>"
        return f"{request.method} {request.url}\n{headers}\n\n{body}"

    def _format_response(self, response):
        if not response: return ""
        headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        body = response.text[:10000] 
        return f"HTTP/1.1 {response.status_code} {response.reason}\n{headers}\n\n{body}"

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
                vuln = {
                    "name": "Clickjacking (UI Redressing)",
                    "severity": "Low",
                    "endpoint": url,
                    "parameter": "HTTP Headers",
                    "payload": "None (Header Missing)",
                    "evidence": evidence.strip(),
                    "action_url": url,
                    "http_method": res.request.method,
                    "input_field_name": "X-Frame-Options / CSP",
                    "request": self._format_request(res.request),
                    "response": self._format_response(res)
                }
                self.vulnerabilities.append(vuln)
                if self.on_vuln:
                    self.on_vuln(vuln)
        except: pass

    def get_results(self):
        return self.vulnerabilities
