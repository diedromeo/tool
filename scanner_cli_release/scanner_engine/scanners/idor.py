
import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner_engine.utils import format_http_request, format_http_response

class IDORScanner:
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
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Target common ID parameters
        id_params = ['id', 'uid', 'user', 'account', 'order', 'doc', 'file', 'invoice', 'profile']
        
        for param in params:
            if not params[param]: continue
            val = params[param][0]
            if not val.isdigit(): continue
            
            is_id_param = any(ip in param.lower() for ip in id_params)
            if not is_id_param: continue

            # Baseline request
            try:
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
                            self._add_vulnerability({
                                "name": "IDOR (Possible)",
                                "severity": "Medium",
                                "endpoint": url,
                                "parameter": param,
                                "payload": str(test_id),
                                "evidence": f"Accessed valid resource with modified ID {test_id}. Status 200, Content Length: {len(res.text)}"
                            }, response=res)
                            break
            except: pass

    def get_results(self):
        return self.vulnerabilities
