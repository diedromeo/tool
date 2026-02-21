
import requests
import time
from scanner_engine.utils import format_http_request, format_http_response

class AuthWeaknessScanner:
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

    def check_brute_force_protection(self, login_url, username_field, password_field):
        """Checks if the login endpoint has rate limiting or lockout."""
        attempts = 5
        results = []
        last_response = None
        
        # We use a non-existent user to avoid accidental lockout of real users
        dummy_data = {
            username_field: "scanner_audit_nonexistent_user",
            password_field: "wrong_password_123"
        }
        
        try:
            for i in range(attempts):
                start = time.time()
                res = self.session.post(login_url, data=dummy_data, timeout=5)
                last_response = res
                duration = time.time() - start
                results.append({"status": res.status_code, "len": len(res.text), "time": duration})
            
            # Analysis
            is_locked = any(r['status'] == 429 for r in results)
            
            if not is_locked:
                self._add_vulnerability({
                    "name": "Authentication Weakness",
                    "severity": "Low",
                    "endpoint": login_url,
                    "parameter": "login_form",
                    "payload": f"{attempts} fast attempts",
                    "evidence": "No rate limiting (HTTP 429) or lockout detected after multiple rapid failed login attempts."
                }, response=last_response)
        except Exception as e:
            import logging
            logging.error(f"Auth Weakness Check Failed: {e}")

    def get_results(self):
        return self.vulnerabilities
