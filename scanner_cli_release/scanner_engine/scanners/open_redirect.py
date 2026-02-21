
import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner_engine.utils import format_http_request, format_http_response

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
                        self._add_vulnerability({
                            "name": "Open Redirect",
                            "severity": "Medium",
                            "endpoint": url,
                            "parameter": param,
                            "payload": load,
                            "evidence": f"Redirect header 'Location' follows payload: {location}"
                        }, response=res)
                        break
                except: pass

    def get_results(self):
        return self.vulnerabilities
