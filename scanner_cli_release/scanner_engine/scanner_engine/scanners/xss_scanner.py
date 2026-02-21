import requests
import re
import threading
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse
import logging
from scanner_engine.payloads import XSS_PAYLOADS

logger = logging.getLogger(__name__)

class XSSScanner:
    def __init__(self, session=None, on_vuln=None):
        self.session = session if session else requests.Session()
        self.vulnerabilities = []
        self.scanned_fingerprints = set()
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
        body = response.text[:10000] # Truncate to avoid huge logs
        return f"HTTP/1.1 {response.status_code} {response.reason}\n{headers}\n\n{body}"

    def _add_vulnerability(self, v_type, severity, url, param, payload, evidence, response_obj=None):
        with self.lock:
            # Prevent duplicate reporting for the same parameter/type
            fingerprint = f"{v_type}:{url}:{param}:{payload}"
            if fingerprint in self.scanned_fingerprints:
                return
            self.scanned_fingerprints.add(fingerprint)
            
            req_str = ""
            res_str = ""
            method = "GET"
            
            if response_obj:
                req_str = self._format_request(response_obj.request)
                res_str = self._format_response(response_obj)
                method = response_obj.request.method

            vuln = {
                "name": v_type,
                "severity": severity,
                "endpoint": url,
                "parameter": param,
                "payload": payload,
                "evidence": evidence[:200],
                "action_url": url,
                "http_method": method,
                "input_field_name": param,
                "request": req_str,
                "response": res_str
            }
            self.vulnerabilities.append(vuln)
            if self.on_vuln:
                self.on_vuln(vuln)

    def scan_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Audit DOM sinks once per URL (Static Analysis)
        # DISABLED to reduce False Positives
        # try:
        #     res = self.session.get(url, timeout=5)
        #     self.audit_dom_sinks(res.text, url)
        # except: pass

        if not params: return

        for param in params:
            for load in XSS_PAYLOADS:
                mp = params.copy()
                mp[param] = [load]
                qs = urlencode(mp, doseq=True)
                t_url = urlunparse(parsed._replace(query=qs))
                try:
                    res = self.session.get(t_url, timeout=5)
                    self._check_reflection(res, load, url, param, "Reflected XSS")
                except: pass

    def scan_form(self, form):
        """Audits a single HTML form for XSS."""
        action = form.get('action')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        payload_data = {}
        for inp in inputs:
            if inp.get('name'):
                payload_data[inp['name']] = "audit_test"

        for inp in inputs:
            if not inp.get('name'): continue
            
            for load in XSS_PAYLOADS:
                test_data = payload_data.copy()
                test_data[inp['name']] = load
                
                try:
                    if method == 'POST':
                        res = self.session.post(action, data=test_data, timeout=5)
                    else:
                        res = self.session.get(action, params=test_data, timeout=5)
                    
                    self._check_reflection(res, load, action, inp['name'], "Form-based XSS")
                except: pass

    def scan_forms(self, forms):
        """Audits all discovered HTML forms for XSS."""
        for form in forms:
            self.scan_form(form)

    def _check_reflection(self, response, payload, url, param, v_prefix):
        """Analyzes how the payload is reflected in the HTML."""
        html = response.text
        
        # 1. Basic Presence Check
        if payload not in html:
            return

        # 2. Encoding Verification
        # If payload contains special chars like < or >, we MUST ensure they are NOT encoded.
        # e.g. if payload is "<script>", and html has "&lt;script&gt;", it is NOT XSS.
        special_chars = ['<', '>', '"', "'"]
        if any(char in payload for char in special_chars):
            # Check if critical characters are encoded in the reflection
            # We pick a segment of the payload that has special chars
            encoded_payload_part = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
            
            # If the encoded version is present but the raw version is NOT (checked above, but context matters)
            # Actually, we verified `payload` (raw) is in `html`.
            # But sometimes `payload` might not have special chars (e.g. `javascript:alert(1)`).
            pass

        # 3. Context Analysis (False Positive Reduction)
        import re
        try:
            escaped_payload = re.escape(payload)
            
            # Check if inside HTML Comments
            if re.search(r'<!--.*?'+escaped_payload+r'.*?-->', html, re.DOTALL):
                return # FP: Inside comment

            # Check if inside non-executable tags: title, textarea, style, xmp, noembed, noscript, iframe
            # This regex looks for an opening tag, the payload, and a closing tag
            dangerous_context = re.search(r'<(textarea|title|style|xmp|noembed|noscript|iframe)[^>]*>.*?'+escaped_payload+r'.*?</\1>', html, re.I | re.DOTALL)
            if dangerous_context:
                return # FP: Inside non-executable tag
        except: pass

        # 4. Vulnerability Classification
        lower_html = html.lower()
        lower_payload = payload.lower()
        
        # A. Reflection in Attribute Value
        # e.g. value="PAYLOAD"
        # We need to check if we broke out of the attribute.
        # If payload is `"><img...`, checking `value=""><img...`
        if f'value="{payload}"' in html or f"value='{payload}'" in html:
             # This is usually NOT XSS unless we broke the quote.
             # If the payload is just `abc`, valid.
             # If payload is `x" onmouseover="alert(1)`, then `value="x" onmouseover="alert(1)"` -> Valid XSS
             
             # If the payload contains valid attribute breakout sequence
             if '"' in payload or "'" in payload:
                 self._add_vulnerability(f"{v_prefix} (Attribute Breakout)", "High", url, param, payload, "Reflected in HTML attribute with potential breakout", response_obj=response)
        
        # B. Script Injection (Reflected Source)
        elif f">{payload}" in html or f"<{payload}" in html or payload.startswith("<script"):
            self._add_vulnerability(f"{v_prefix} (Script Injection)", "Critical", url, param, payload, "Unfiltered script/tag injection", response_obj=response)
            
        # C. JavaScript Context
        elif "var " in html and payload in html:
             # Very heuristic, check if it's inside a script tag
             script_context = re.search(r'<script[^>]*>.*?'+re.escape(payload)+r'.*?</script>', html, re.I | re.DOTALL)
             if script_context:
                 self._add_vulnerability(f"{v_prefix} (JS Context)", "High", url, param, payload, "Reflected inside <script> block", response_obj=response)

        # D. Generic Reflection - DOWNGRADED or IGNORED
        else:
            # We strictly ignore generic reflection to satisfy "False Positive Engine" rules.
            # "Payload reflected in response" is not proof of exploitability.
            pass

    def audit_dom_sinks(self, html, url):
        """Static analysis of JavaScript to find potential DOM XSS sinks."""
        dangerous_patterns = [
            (r"\.innerHTML\s*=", "DOM-based XSS (innerHTML Sink)"),
            (r"document\.write\(", "DOM-based XSS (document.write Sink)"),
            (r"eval\(", "Potential DOM XSS (eval Sink)"),
            (r"setTimeout\([^,]+,/", "Potential DOM XSS (setTimeout Sink)"),
            (r"\.src\s*=\s*['\"]javascript:", "DOM-based XSS (Dynamic Script Source)")
        ]
        
        # Look for sources
        sources = [r"location\.", r"document\.referrer", r"window\.name", r"location\.hash"]
        
        has_source = any(re.search(src, html, re.I) for src in sources)
        
        if has_source:
            for pattern, v_name in dangerous_patterns:
                match = re.search(pattern, html, re.I)
                if match:
                    self._add_vulnerability(v_name, "High", url, "JavaScript Sink", "Static Analysis", f"Found sink: {match.group(0)}")

    def get_results(self):
        return self.vulnerabilities
