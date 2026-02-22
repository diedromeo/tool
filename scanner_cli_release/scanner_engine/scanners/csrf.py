import requests
from scanner_engine.utils import format_http_request, format_http_response

class CSRFScanner:
    def __init__(self, session=None, on_vuln=None):
        self.session = session if session else requests.Session()
        self.vulnerabilities = []
        self.on_vuln = on_vuln
        self.scanned_urls = set()

    def _add_vulnerability(self, data, response=None):
        if response:
            data['request'] = format_http_request(response.request)
            data['response'] = format_http_response(response)
        
        # Deduplication per action URL
        if data['endpoint'] in self.scanned_urls:
            return
        self.scanned_urls.add(data['endpoint'])
        
        self.vulnerabilities.append(data)
        if self.on_vuln:
            self.on_vuln(data)

    def scan_form(self, form):
        action = form.get('action')
        if not action: return
        
        inputs = form.get('inputs', [])
        tokens = ['csrf_token', 'csrfmiddlewaretoken', '_csrf', 'xsrf_token', 'user_token', 'token']
        
        has_token = False
        for inp in inputs:
            name = inp.get('name', '').lower()
            if name in tokens:
                has_token = True
                break
        
        if not has_token:
            self._add_vulnerability({
                "name": "Missing CSRF", 
                "severity": "Medium",
                "endpoint": action, 
                "parameter": "Form",
                "payload": "-", 
                "evidence": "No token",
                "action_url": action,
                "input_field_name": "Form",
                "http_method": form.get('method', 'GET').upper(),
                "owasp_reference": "https://owasp.org/www-community/attacks/csrf",
                "owasp_id": "A01:2021-Broken Access Control",
                "poc_url": f"{action}?Form=-"
            })

    def scan_forms(self, forms): 
        for form in forms: 
            self.scan_form(form)

    def get_results(self):
        return self.vulnerabilities
