import requests
import logging
import threading
import urllib.parse
from scanner_engine.utils import format_http_request, format_http_response

class CommandInjectionScanner:
    def __init__(self, session=None, on_vuln=None):
        self.session = session if session else requests.Session()
        self.signatures = ["VULN_CHECK"]
        self.on_vuln = on_vuln
        self.vulnerabilities = []
        self.scanned_fingerprints = set()
        self.lock = threading.Lock()
        self.payloads = [
            "; echo VULN_CHECK",
            "| echo VULN_CHECK",
            "& echo VULN_CHECK",
            "\n echo VULN_CHECK",
            "$(echo VULN_CHECK)",
            "`echo VULN_CHECK`"
        ]
        
    def scan_url(self, url):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return
            
        for param, values in params.items():
            for payload in self.payloads:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    resp = self.session.get(url.split('?')[0], params=test_params, timeout=20)
                    if self._analyze(resp, param, payload, url.split('?')[0]): break
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
                
        # Ensure a submit button is present if we found inputs
        submit_added = False
        for inp in inputs:
            if inp.get('type') == 'submit' or 'submit' in inp.get('name', '').lower():
                base_data[inp.get('name', 'Submit')] = inp.get('value', 'Submit')
                submit_added = True
                break
        if not submit_added and inputs:
            base_data['Submit'] = 'Submit'

        for inp in inputs:
            name = inp.get('name')
            if not name or inp.get('type') in ['submit', 'button']: continue
            
            for payload in self.payloads:
                data = base_data.copy()
                data[name] = payload
                try:
                    if method == 'POST':
                        resp = self.session.post(action, data=data, timeout=20)
                    else:
                        resp = self.session.get(action, params=data, timeout=20)
                    
                    if self._analyze(resp, name, payload, action): break
                except:
                    pass

    def _analyze(self, resp, param, payload, endpoint):
         for sig in self.signatures:
             if sig in resp.text:
                 with self.lock:
                     # Deduplicate
                     fingerprint = f"{endpoint}:{param}"
                     if fingerprint in self.scanned_fingerprints:
                         return True
                     self.scanned_fingerprints.add(fingerprint)
                 
                 vuln = {
                     "name": "Command Injection (RCE)",
                     "severity": "Critical",
                     "endpoint": endpoint,
                     "parameter": param,
                     "payload": payload,
                     "evidence": f"Found signature '{sig}' in response body.",
                     "owasp_reference": "https://owasp.org/www-community/attacks/Command_Injection",
                     "owasp_id": "A03:2021-Injection",
                     "request": format_http_request(resp.request),
                     "response": format_http_response(resp)
                 }
                 self.vulnerabilities.append(vuln)
                 if self.on_vuln:
                     self.on_vuln(vuln)
                 return True
         return False

    def get_results(self):
        return self.vulnerabilities
