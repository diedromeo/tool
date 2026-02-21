
import requests
from scanner_engine.utils import format_http_request, format_http_response

class CORSScanner:
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
            # Test 1: Wildcard Origin
            res = self.session.get(url, timeout=5)
            origin = res.headers.get('Access-Control-Allow-Origin', '')
            
            if origin == '*':
                self._add_vulnerability({
                    "name": "CORS Misconfiguration (Wildcard)",
                    "severity": "Low",
                    "endpoint": url,
                    "parameter": "Access-Control-Allow-Origin",
                    "payload": "Origin: *",
                    "evidence": "Access-Control-Allow-Origin header is set to '*', allowing any domain to read response data."
                }, response=res)
            
            # Test 2: Reflective Origin (Trusting any origin)
            test_origin = "https://evil-attacker-domain.com"
            headers = {"Origin": test_origin}
            res_reflected = self.session.get(url, headers=headers, timeout=5)
            
            if res_reflected.headers.get('Access-Control-Allow-Origin') == test_origin:
                self._add_vulnerability({
                    "name": "CORS Misconfiguration (Reflective)",
                    "severity": "Medium",
                    "endpoint": url,
                    "parameter": "Origin Header",
                    "payload": f"Origin: {test_origin}",
                    "evidence": f"Server reflects the Origin header back in Access-Control-Allow-Origin, trusting any arbitrary domain."
                }, response=res_reflected)
        except: pass

    def get_results(self):
        return self.vulnerabilities
