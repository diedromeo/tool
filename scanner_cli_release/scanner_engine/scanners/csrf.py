
import requests
from scanner_engine.utils import format_http_request, format_http_response

class CSRFScanner:
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

    def scan_forms(self, forms): 
        for form in forms: 
            if form.get('method', 'GET').upper() != 'POST': continue

            action = form.get('action')
            inputs = form.get('inputs', [])
            tokens = ['csrf_token', 'csrfmiddlewaretoken', '_csrf', 'xsrf_token', 'user_token']
    
            has = False
            for inp in inputs:
                if inp.get('name') and inp.get('name').lower() in tokens:
                    has = True; break
            
            if not has:
                self._add_vulnerability({
                    "name": "Missing CSRF Protection", 
                    "severity": "Medium",
                    "endpoint": action, 
                    "parameter": "Form",
                    "payload": "N/A", 
                    "evidence": "HTML form lacks a common CSRF anti-forgery token in its fields."
                })

    def get_results(self):
        return self.vulnerabilities
