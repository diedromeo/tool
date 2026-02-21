
import requests
import time

class AuthWeaknessScanner:
    def __init__(self, session=None, on_vuln=None):
        self.session = session if session else requests.Session()
        self.vulnerabilities = []
        self.vulnerabilities = []
        self.on_vuln = on_vuln

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


    def check_brute_force_protection(self, login_url, username_field, password_field):
        """Checks if the login endpoint has rate limiting or lockout."""
        attempts = 5
        results = []
        
        # We use a non-existent user to avoid accidental lockout of real users
        dummy_data = {
            username_field: "scanner_audit_nonexistent_user",
            password_field: "wrong_password_123"
        }
        
        try:
            for i in range(attempts):
                start = time.time()
                res = self.session.post(login_url, data=dummy_data, timeout=5)
                duration = time.time() - start
                results.append({"status": res.status_code, "len": len(res.text), "time": duration})
            
            # Analysis
            is_locked = any(r['status'] == 429 for r in results)
            
            if not is_locked:
                vuln = {
                    "name": "Authentication Weakness",
                    "severity": "Low",
                    "endpoint": login_url,
                    "parameter": "login_form",
                    "payload": f"{attempts} fast attempts",
                    "evidence": "No rate limiting (HTTP 429) or lockout detected after multiple rapid failed login attempts.",
                    "action_url": login_url,
                    "http_method": "POST",
                    "input_field_name": "login_form",
                    "request": self._format_request(res.request) if 'res' in locals() else "",
                    "response": self._format_response(res) if 'res' in locals() else ""
                }
                self.vulnerabilities.append(vuln)
                if self.on_vuln:
                    self.on_vuln(vuln)
        except Exception as e:
            import logging
            logging.error(f"Auth Weakness Check Failed: {e}")

    def get_results(self):
        return self.vulnerabilities
