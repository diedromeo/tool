import requests
import time
import logging
import threading
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' AND SLEEP(5)--"
]

IGNORED_PARAMS = [
    '__VIEWSTATE',
    '__EVENTVALIDATION',
    'csrf_token',
    'csrf',
    'token',
    '_token',
    'submit',
    'btn',
    'button',
    'action'
]

SQL_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-",
    "PostgreSQL",
    "Unclosed quotation mark",
    "valid MySQL result",
    "ODBC SQL Server Driver",
    "Microsoft OLE DB Provider for SQL Server",
    "You have an error in your SQL syntax"
]

class SQLIScanner:
    def __init__(self, session=None, on_vuln=None):
        self.session = session if session else requests.Session()
        self.vulnerabilities = []
        self.on_vuln = on_vuln
        self.lock = threading.Lock()

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


    def _add_vulnerability(self, data):
        with self.lock:
            self.vulnerabilities.append(data)
            if self.on_vuln:
                self.on_vuln(data)

    def scan_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        for param in params:
            if any(ign in param.lower() for ign in IGNORED_PARAMS):
                continue
                
            for load in SQLI_PAYLOADS:
                mp = params.copy()
                mp[param] = [load]
                qs = urlencode(mp, doseq=True)
                t_url = urlunparse(parsed._replace(query=qs))
                try:
                    s_time = time.time()
                    baseline_res = self.session.get(url, timeout=10)
                    baseline_time = time.time() - s_time
                    
                    s_time = time.time()
                    res = self.session.get(t_url, timeout=10)
                    elapsed = time.time() - s_time
                    
                    # Stricter Boolean/Error Check
                    has_error = any(e.lower() in res.text.lower() for e in SQL_ERRORS)
                    if has_error:
                        self._add_vulnerability({
                            "name": "SQL Injection (Error-Based)", 
                            "severity": "Critical",
                            "endpoint": url, "parameter": param,
                            "payload": load, "evidence": "Specific SQL error message found in response",
                            "action_url": url,
                            "http_method": res.request.method,
                            "input_field_name": param,
                            "request": self._format_request(res.request),
                            "response": self._format_response(res)
                        })
                        break
                    
                    # Stricter Time-Based Check
                    if "SLEEP" in load and elapsed > (baseline_time + 4):
                        self._add_vulnerability({
                            "name": "SQL Injection (Time-Based)", 
                            "severity": "Critical",
                            "endpoint": url, "parameter": param,
                            "payload": load, "evidence": f"Delay {round(elapsed, 2)}s significantly > baseline {round(baseline_time, 2)}s",
                            "action_url": url,
                            "http_method": res.request.method,
                            "input_field_name": param,
                            "request": self._format_request(res.request),
                            "response": self._format_response(res)
                        })
                        break
                except: pass

    def scan_form(self, form):
        """Audits a single HTML form for SQL Injection."""
        action = form.get('action') 
        if not action: return
        
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', []) # list of dicts {name, type}
        
        # Prepare base data
        base_data = {}
        for inp in inputs:
            if inp.get('name'):
                base_data[inp['name']] = "1"

        for inp in inputs:
            if not inp.get('name'): continue
            
            param = inp['name']
            if any(ign in param.lower() for ign in IGNORED_PARAMS):
                continue
            
            for load in SQLI_PAYLOADS:
                test_data = base_data.copy()
                test_data[param] = load
                
                try:
                    baseline_start = time.time()
                    if method == 'POST':
                        self.session.post(action, data=base_data, timeout=10)
                    else:
                        self.session.get(action, params=base_data, timeout=10)
                    baseline_time = time.time() - baseline_start

                    s_time = time.time()
                    if method == 'POST':
                        res = self.session.post(action, data=test_data, timeout=10)
                    else:
                        res = self.session.get(action, params=test_data, timeout=10)
                    elapsed = time.time() - s_time
                    
                    has_error = any(e.lower() in res.text.lower() for e in SQL_ERRORS)
                    if has_error:
                         self._add_vulnerability({
                            "name": "SQL Injection (Form-Based/Error)", 
                            "severity": "Critical",
                            "endpoint": action, "parameter": param,
                            "payload": load, "evidence": "Specific SQL error message found in response",
                            "action_url": action,
                            "http_method": res.request.method,
                            "input_field_name": param,
                            "request": self._format_request(res.request),
                            "response": self._format_response(res)
                        })
                         break
                    
                    if "SLEEP" in load and elapsed > (baseline_time + 4):
                         self._add_vulnerability({
                            "name": "SQL Injection (Form-Based/Time)", 
                            "severity": "Critical",
                            "endpoint": action, "parameter": param,
                            "payload": load, "evidence": f"Delay {round(elapsed, 2)}s significantly > baseline {round(baseline_time, 2)}s",
                            "action_url": action,
                            "http_method": res.request.method,
                            "input_field_name": param,
                            "request": self._format_request(res.request),
                            "response": self._format_response(res)
                        })
                         break
                except Exception as e:
                    logging.error(f"SQLi Form Scan Error on {action}: {e}")

    def scan_forms(self, forms):
        """Audits all discovered HTML forms for SQL Injection."""
        for form in forms:
            self.scan_form(form)

    def get_results(self):
        return self.vulnerabilities
