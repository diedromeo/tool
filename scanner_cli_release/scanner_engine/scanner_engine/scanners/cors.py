
import requests

class CORSScanner:
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
            # Test 1: Wildcard Origin
            res = self.session.get(url, timeout=5)
            origin = res.headers.get('Access-Control-Allow-Origin', '')
            
            if origin == '*':
                vuln = {
                    "name": "CORS Misconfiguration (Wildcard)",
                    "severity": "Low",
                    "endpoint": url,
                    "parameter": "Access-Control-Allow-Origin",
                    "payload": "Origin: *",
                    "evidence": "Access-Control-Allow-Origin header is set to '*', allowing any domain to read response data.",
                    "action_url": url,
                    "http_method": res.request.method,
                    "input_field_name": "Access-Control-Allow-Origin",
                    "request": self._format_request(res.request),
                    "response": self._format_response(res)
                }
                self.vulnerabilities.append(vuln)
                if self.on_vuln:
                    self.on_vuln(vuln)
            
            # Test 2: Reflective Origin (Trusting any origin)
            test_origin = "https://evil-attacker-domain.com"
            headers = {"Origin": test_origin}
            res_reflected = self.session.get(url, headers=headers, timeout=5)
            
            if res_reflected.headers.get('Access-Control-Allow-Origin') == test_origin:
                vuln = {
                    "name": "CORS Misconfiguration (Reflective)",
                    "severity": "Medium",
                    "endpoint": url,
                    "parameter": "Origin Header",
                    "payload": f"Origin: {test_origin}",
                    "evidence": f"Server reflects the Origin header back in Access-Control-Allow-Origin, trusting any arbitrary domain.",
                    "action_url": url,
                    "http_method": res_reflected.request.method,
                    "input_field_name": "Origin",
                    "request": self._format_request(res_reflected.request),
                    "response": self._format_response(res_reflected)
                }
                self.vulnerabilities.append(vuln)
                if self.on_vuln:
                    self.on_vuln(vuln)
        except: pass

    def get_results(self):
        return self.vulnerabilities
