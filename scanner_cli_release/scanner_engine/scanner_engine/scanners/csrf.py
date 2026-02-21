
import requests

class CSRFScanner:
    def __init__(self, session=None, on_vuln=None):
        self.session = session if session else requests.Session()
        self.vulnerabilities = []
        self.vulnerabilities = []
        self.on_vuln = on_vuln

    def _format_request(self, request):
        if not request: return ""
        try:
            headers = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
            body = request.body if request.body else ""
            if isinstance(body, bytes):
                try: body = body.decode('utf-8', errors='ignore')
                except: body = "<binary data>"
            return f"{request.method} {request.url}\n{headers}\n\n{body}"
        except: return str(request)

    def _format_response(self, response):
        if not response: return ""
        try:
            headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
            body = response.text[:10000] 
            return f"HTTP/1.1 {response.status_code} {response.reason}\n{headers}\n\n{body}"
        except: return str(response)


    def scan_forms(self, forms): 
        for form in forms: 
            if form.get('method', 'GET').upper() != 'POST': continue

            action = form.get('action')
            inputs = form.get('inputs', [])
            tokens = ['csrf_token', 'csrfmiddlewaretoken', '_csrf', 'xsrf_token']
    
            has = False
            for inp in inputs:
                if inp['name'].lower() in tokens:
                    has = True; break
            
            if not has:
                vuln = {
                    "name": "Missing CSRF Token", "severity": "Medium",
                    "endpoint": action, "parameter": "Form",
                    "payload": "-", "evidence": "No anti-CSRF token found in form fields.",
                    "action_url": action,
                    "http_method": form.get('method', 'GET').upper(),
                    "input_field_name": "Form Inputs",
                    "request": "N/A (Static Analysis)",
                    "response": "N/A (Static Analysis)"
                }
                self.vulnerabilities.append(vuln)
                if self.on_vuln:
                    self.on_vuln(vuln)

    def get_results(self):
        return self.vulnerabilities
