
import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

REDIRECT_PAYLOADS = [
    "https://google.com",
    "//google.com",
    "https:google.com",
    "/\//google.com"
]

class RedirectScanner:
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
        
        # Target common redirect parameters
        redirect_params = ['next', 'url', 'redirect', 'return', 'dest', 'destination', 'continue', 'u']
        
        for param in params:
            is_redirect_param = any(rp in param.lower() for rp in redirect_params)
            
            for load in REDIRECT_PAYLOADS:
                mp = params.copy()
                mp[param] = [load]
                qs = urlencode(mp, doseq=True)
                t_url = urlunparse(parsed._replace(query=qs))
                
                try:
                    # Don't follow redirects automatically so we can check the Location header
                    res = self.session.get(t_url, timeout=5, allow_redirects=False)
                    
                    location = res.headers.get('Location', '')
                    if res.status_code in [301, 302, 303, 307, 308] and "google.com" in location:
                        vuln = {
                            "name": "Open Redirect",
                            "severity": "Medium",
                            "endpoint": url,
                            "parameter": param,
                            "payload": load,
                            "evidence": f"Redirect header 'Location' follows payload: {location}",
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
