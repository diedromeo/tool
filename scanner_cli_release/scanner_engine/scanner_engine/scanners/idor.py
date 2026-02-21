
import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class IDORScanner:
    def __init__(self, session=None, on_vuln=None):
        self.session = session if session else requests.Session()
        self.vulnerabilities = []
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
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Target common ID parameters
        id_params = ['id', 'uid', 'user', 'account', 'order', 'doc', 'file', 'invoice', 'profile']
        
        for param in params:
            val = params[param][0]
            if not val.isdigit(): continue
            
            is_id_param = any(ip in param.lower() for ip in id_params)
            if not is_id_param: continue

            # Baseline request
            try:
                original_res = self.session.get(url, timeout=5)
                
                # Try to access a different ID (±1)
                for drift in [1, -1]:
                    test_id = int(val) + drift
                    if test_id < 0: continue
                    
                    mp = params.copy()
                    mp[param] = [str(test_id)]
                    qs = urlencode(mp, doseq=True)
                    t_url = urlunparse(parsed._replace(query=qs))
                    
                    res = self.session.get(t_url, timeout=5)
                    
                    if res.status_code == 200 and len(res.text) > 200:
                        error_keywords = ['error', 'denied', 'unauthorized', 'forbidden', 'invalid']
                        if not any(kw in res.text.lower() for kw in error_keywords):
                            vuln = {
                                "name": "IDOR (Possible)",
                                "severity": "Medium",
                                "endpoint": url,
                                "parameter": param,
                                "payload": str(test_id),
                                "evidence": f"Accessed valid resource with modified ID {test_id}. Status 200, Content Length: {len(res.text)}",
                                "action_url": url,
                                "http_method": res.request.method,
                                "input_field_name": param,
                                "request": self._format_request(res.request),
                                "response": self._format_response(res)
                            }
                            self.vulnerabilities.append(vuln)
                            if self.on_vuln:
                                self.on_vuln(vuln)
                            break
            except: pass

    def get_results(self):
        return self.vulnerabilities
