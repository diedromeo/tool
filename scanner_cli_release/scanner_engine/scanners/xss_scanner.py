import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from scanner_engine.utils import format_http_request, format_http_response
import logging
import threading

logger = logging.getLogger(__name__)

class XSSScanner:
    def __init__(self, session=None, on_vuln=None):
        self.session = session if session else requests.Session()
        self.on_vuln = on_vuln
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.scanned_records = set() # (type, url, param)
        self.payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]

    def _add_vulnerability(self, data, response=None):
        if response:
            data['request'] = format_http_request(response.request)
            data['response'] = format_http_response(response)
        
        with self.lock:
            # Deduplicate by type + endpoint + parameter
            # We allow multiple payloads if they result in different "types" of XSS 
            # (e.g. Reflected vs Form-based), but generally we want one report per parameter.
            record = (data['name'], data['endpoint'], data['parameter'])
            if record in self.scanned_records:
                return
            self.scanned_records.add(record)
            
            self.vulnerabilities.append(data)
            if self.on_vuln:
                self.on_vuln(data)

    def scan_url(self, url):
        parsed = urlparse(url)
        params = parsed.query.split('&')
        if not params or params == ['']:
            return

        for p in params:
            if '=' not in p: continue
            key = p.split('=')[0]
            for payload in self.payloads:
                t_url = url.replace(f"{key}={p.split('=')[1]}", f"{key}={payload}")
                try:
                    res = self.session.get(t_url, timeout=10)
                    if payload in res.text:
                        self._add_vulnerability({
                            "name": "Reflected XSS",
                            "severity": "Critical",
                            "endpoint": url,
                            "parameter": key,
                            "payload": payload,
                            "evidence": f"Payload detected in response from {t_url}"
                        }, response=res)
                        break
                except: pass

    def scan_form(self, form):
        action = form.get('action')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        base_data = {}
        for inp in inputs:
            name = inp.get('name')
            if name:
                base_data[name] = inp.get('value', '')

        for inp in inputs:
            name = inp.get('name')
            if not name or inp.get('type') in ['submit', 'button']: continue
            
            for payload in self.payloads:
                test_data = base_data.copy()
                test_data[name] = payload
                try:
                    if method == 'POST':
                        res = self.session.post(action, data=test_data, timeout=10)
                    else:
                        res = self.session.get(action, params=test_data, timeout=10)
                    
                    if payload in res.text:
                        self._add_vulnerability({
                            "name": "Form-based XSS (Script Injection)",
                            "severity": "Critical",
                            "endpoint": action,
                            "parameter": name,
                            "payload": payload,
                            "evidence": "Unfiltered script/tag injection"
                        }, response=res)
                        break
                except: pass

    def scan_forms(self, forms):
        for form in forms:
            self.scan_form(form)

    def get_results(self):
        return self.vulnerabilities
