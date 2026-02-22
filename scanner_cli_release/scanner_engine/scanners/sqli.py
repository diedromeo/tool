import requests
import time
import logging
import threading
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse
from scanner_engine.utils import format_http_request, format_http_response

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' AND SLEEP(5)--"
]

class SQLIScanner:
    def __init__(self, session=None, on_vuln=None):
        self.session = session if session else requests.Session()
        self.vulnerabilities = []
        self.on_vuln = on_vuln
        self.lock = threading.Lock()
        self.scanned_fingerprints = set()

    def _add_vulnerability(self, data, response=None):
        if response:
            data['request'] = format_http_request(response.request)
            data['response'] = format_http_response(response)
            
        with self.lock:
            # Deduplicate by endpoint + parameter
            fingerprint = f"{data['endpoint']}:{data['parameter']}"
            if fingerprint in self.scanned_fingerprints:
                return
            self.scanned_fingerprints.add(fingerprint)
            
            self.vulnerabilities.append(data)
            if self.on_vuln:
                self.on_vuln(data)

    def scan_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        for param in params:
            for load in SQLI_PAYLOADS:
                mp = params.copy()
                mp[param] = [load]
                qs = urlencode(mp, doseq=True)
                t_url = urlunparse(parsed._replace(query=qs))
                try:
                    s_time = time.time()
                    res = self.session.get(t_url, timeout=10)
                    elapsed = time.time() - s_time
                    
                    err_sigs = ["sql syntax", "mysql_fetch", "mysql_num_rows", "mysql_query", "mysqli_", "pdo exception"]
                    if any(sig in res.text.lower() for sig in err_sigs):
                        self._add_vulnerability({
                            "name": "SQL Injection (Error-Based)", 
                            "severity": "Critical",
                            "endpoint": url, "parameter": param,
                            "payload": load, "evidence": "Error reflection in response"
                        }, response=res)
                        break
                    
                    if "SLEEP" in load and elapsed > 4:
                        self._add_vulnerability({
                            "name": "SQL Injection (Time-Based)", 
                            "severity": "Critical",
                            "endpoint": url, "parameter": param,
                            "payload": load, "evidence": f"Significant delay detected: {round(elapsed, 2)}s"
                        }, response=res)
                        break
                except: pass

    def scan_form(self, form):
        """Audits a single HTML form for SQL Injection."""
        action = form.get('action') 
        if not action: return
        
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        base_data = {}
        for inp in inputs:
            name = inp.get('name')
            if name:
                base_data[name] = inp.get('value', '1') or '1'

        for inp in inputs:
            if not inp.get('name') or inp.get('type') in ['submit', 'button', 'hidden']: continue
            param = inp['name']
            
            for load in SQLI_PAYLOADS:
                test_data = base_data.copy()
                test_data[param] = load
                
                try:
                    s_time = time.time()
                    if method == 'POST':
                        res = self.session.post(action, data=test_data, timeout=10)
                    else:
                        res = self.session.get(action, params=test_data, timeout=10)
                    elapsed = time.time() - s_time
                    
                    err_sigs = ["sql syntax", "mysql_fetch", "mysql_num_rows", "mysqli_", "pdo exception", "driver error"]
                    if any(sig in res.text.lower() for sig in err_sigs):
                        self._add_vulnerability({
                            "name": "SQL Injection (Form-Based/Error)", 
                            "severity": "Critical",
                            "endpoint": action, "parameter": param,
                            "payload": load, "evidence": "Error reflection in response"
                        }, response=res)
                        break
                    
                    if "SLEEP" in load and elapsed > 4:
                        self._add_vulnerability({
                            "name": "SQL Injection (Form-Based/Time)", 
                            "severity": "Critical",
                            "endpoint": action, "parameter": param,
                            "payload": load, "evidence": f"Significant delay detected: {round(elapsed, 2)}s"
                        }, response=res)
                        break
                except: pass

    def get_results(self):
        return self.vulnerabilities
