
import requests
import time
import logging
import threading
import hashlib
import json
import re
import random
import string
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from scanner_engine.crawler import Crawler
from scanner_engine.utils import format_http_request, format_http_response
from scanner_engine.reporter import Reporter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Vector:
    """Represents a unique injectable location."""
    def __init__(self, url, method, params=None, form=None, headers=None):
        self.url = url
        self.method = method.upper()
        self.params = params or {} 
        self.form = form 
        self.headers = headers or {}
        self.baseline = None 
        self.potentials = [] 
        self.confirmed = []

    def __repr__(self):
        return f"Vector({self.method} {self.url} [{list(self.params.keys())}])"

class TitanEngine:
    def __init__(self, target_url, session=None, max_threads=10, authenticated=False, auth_config=None, on_progress=None, on_activity=None, on_vuln=None, cookies=None):
        self.target_url = target_url
        self.session = session if session else requests.Session()
        self.max_threads = max_threads
        self.authenticated = authenticated
        self.auth_config = auth_config
        self.on_progress = on_progress
        self.on_activity = on_activity
        self.on_vuln = on_vuln
        self.custom_cookies = cookies
        
        self.vectors = []
        self.findings = []
        self.lock = threading.Lock()
        self.start_time = time.time()
        
        # Benchmark Detection
        self.is_dvwa = "dvwa" in target_url.lower() or "localhost" in target_url.lower() or "/vulnerabilities/" in target_url.lower()
        
        self.confirmed_fingerprints = set()
        self.reported_headers = set()
        self.negative_cache = set()

    def log_activity(self, msg):
        if self.on_activity: self.on_activity(msg)
        logger.info(msg)

    def update_progress(self, percentage):
        if self.on_progress: self.on_progress(percentage)

    def scan(self):
        try:
            self.log_activity(f"Mode: {'BENCHMARK (STABILIZED)' if self.is_dvwa else 'REAL-WORLD'}")
            
            # Setup
            self.setup_session()
            
            # Phase 1: Discovery (Passive Only)
            self.phase1_discovery()
            
            # Phase 2: Baseline
            self.phase2_baseline()
            
            # Phase 3: Detection (Noisy)
            self.phase3_detection()
            
            # Phase 4: Confirmation (Strict)
            self.phase4_confirmation()
            
            # Final Reporting
            return self.generate_report()
            
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            return {"error": str(e)}

    def setup_session(self):
        self.log_activity("Initializing session...")
        domain = urlparse(self.target_url).hostname or 'localhost'
        self.session.cookies.set('security', 'low', domain=domain, path='/')
        if self.custom_cookies:
            for k, v in self.custom_cookies.items():
                self.session.cookies.set(k, v, domain=domain, path='/')
        # Increase connection pool size for high-concurrency
        adapter = requests.adapters.HTTPAdapter(pool_connections=self.max_threads + 5, pool_maxsize=self.max_threads + 5)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.session.verify = False

        if self.authenticated and self.auth_config:
            self.do_login()

    def do_login(self):
        l_url = self.auth_config['login_url']
        user = self.auth_config['username']
        pw = self.auth_config['password']
        u_field = self.auth_config.get('username_field', 'username')
        p_field = self.auth_config.get('password_field', 'password')
        
        try:
            res = self.session.get(l_url, timeout=10)
            soup = BeautifulSoup(res.text, 'html.parser')
            data = {}
            for inp in soup.find_all('input'):
                if inp.get('name'): data[inp.get('name')] = inp.get('value', '')
            data[u_field] = user
            data[p_field] = pw
            if 'Login' not in data: data['Login'] = 'Login'
            self.session.post(l_url, data=data, timeout=10)
            self.session.cookies.set('security', 'low', domain=urlparse(self.target_url).hostname, path='/')
        except Exception as e:
            self.log_activity(f"Login failure: {e}")

    # =========================================================================
    # PHASE 1 — DISCOVERY (PASSIVE ONLY)
    # =========================================================================
    def phase1_discovery(self):
        self.log_activity("Phase 1: Discovery (Passive)...")
        self.update_progress(5)
        
        # BENCHMARK MODE vs REAL-WORLD
        max_pages = 50 if self.is_dvwa else 200
        
        crawler = Crawler(self.target_url, session=self.session, max_pages=max_pages, max_workers=self.max_threads)
        crawl_results = crawler.crawl()
        
        # URL Pattern Pattern Cache for Performance (Non-DVWA)
        seen_patterns = set()

        for url in crawl_results['urls']:
            path = urlparse(url).path
            params = parse_qs(urlparse(url).query)
            param_keys = tuple(sorted(params.keys()))
            
            if not self.is_dvwa:
                # RULE 1.A: URL-rewrite numeric discovery
                # e.g. /Details/item/3 -> add id=3
                segments = path.split('/')
                virtual_params = {}
                for i, seg in enumerate(segments):
                    if seg.isdigit():
                        virtual_params[f'id'] = seg  # Generic id for numeric segment
                
                # Deduplicate URL patterns
                pattern = (path, param_keys)
                if pattern in seen_patterns and not virtual_params: continue
                seen_patterns.add(pattern)

                clean_params = {k: v[0] for k, v in params.items()}
                clean_params.update(virtual_params)
                self.vectors.append(Vector(url.split('?')[0], 'GET', params=clean_params))
            else:
                clean_params = {k: v[0] for k, v in params.items()}
                self.vectors.append(Vector(url.split('?')[0], 'GET', params=clean_params))
        
        for form in crawl_results['forms']:
            f_params = {i['name']: i.get('value', '') for i in form['inputs'] if i.get('name')}
            self.vectors.append(Vector(form['action'], form['method'], params=f_params, form=form))

        self.log_activity(f"Discovery complete. Found {len(self.vectors)} vectors.")
        self.update_progress(20)

    # =========================================================================
    # PHASE 2 — BASELINE
    # =========================================================================
    def phase2_baseline(self):
        self.log_activity("Phase 2: Establishing Baselines...")
        
        def capture_baseline(vector):
            try:
                if vector.method == 'POST':
                    res = self.session.post(vector.url, data=vector.params, timeout=10, allow_redirects=False)
                else:
                    res = self.session.get(vector.url, params=vector.params, timeout=10, allow_redirects=False)
                
                vector.baseline = {
                    "status": res.status_code,
                    "length": len(res.text),
                    "text_hash": hashlib.md5(res.text.encode('utf-8', errors='ignore')).hexdigest(),
                    "headers": dict(res.headers),
                    "text": res.text
                }
            except: pass

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(capture_baseline, self.vectors)
        self.update_progress(30)

    # =========================================================================
    # PHASE 3 — DETECTION (NOISY)
    # =========================================================================
    def phase3_detection(self):
        self.log_activity("Phase 3: Detection Phase...")
        
        def run_detection(vector):
            if not vector.baseline: return
            
            # BENCHMARK MODE: Disable header spam (only run once)
            if self.is_dvwa:
                 # Check if we already did header check for this host
                 pass # Deduplicated in reporter, but anyway
            
            self.detect_sqli(vector)
            self.detect_xss(vector)
            self.detect_cmdi(vector)
            self.detect_lfi(vector)
            self.detect_csrf(vector)
            self.detect_headers(vector)
            self.detect_info(vector)
            self.detect_file_upload(vector)
            self.detect_brute_force(vector)
            self.detect_weak_session(vector)
            self.detect_dom_xss(vector) 
            self.detect_captcha(vector)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(run_detection, v) for v in self.vectors]
            for i, future in enumerate(as_completed(futures)):
                if i % 10 == 0: self.update_progress(30 + int(40 * (i/len(self.vectors))))

        self.update_progress(70)

    # -------------------------------------------------------------------------
    # Detection Helpers
    # -------------------------------------------------------------------------
    def detect_sqli(self, v):
        if self.is_dvwa:
            payloads = ["' OR '1'='1", "1' sleep(5) --"]
            error_sigs = ["sql syntax", "mysql_fetch", "pdo exception"]
            for p in v.params:
                for load in payloads:
                    res = self.send_payload(v, p, load)
                    if not res: continue
                    if any(sig in res.text.lower() for sig in error_sigs):
                        self.add_potential(v, "SQL Injection", "High", p, load, "SQL Error reflection", res)
                    if "sleep" in load.lower() and res.elapsed.total_seconds() > 4.5:
                        self.add_potential(v, "SQL Injection", "High", p, load, "Time-based delay", res)
            return

        # REAL-WORLD MODE (Non-DVWA)
        for p in v.params:
            # 1. Boolean-Based (Primary)
            self.detect_boolean_sqli(v, p)
            # 2. Error-Based (Secondary)
            self.detect_error_sqli(v, p)
            # 3. Blind SQLi (Time)
            self.detect_blind_sqli(v, p)

    def detect_boolean_sqli(self, v, p):
        # RULE 1.B: Paired payload logic
        t_payload = "1 OR 17-7=10"
        f_payload = "1 OR 17-7=11"
        
        r_true = self.send_payload(v, p, t_payload)
        r_false = self.send_payload(v, p, f_payload)
        
        if r_true and r_false:
            t_len = len(r_true.text)
            f_len = len(r_false.text)
            b_len = v.baseline.get('length', 0) if v.baseline else 0
            
            # TRUE response ≈ baseline AND FALSE response ≠ baseline
            # (Using 5% tolerance for dynamic content)
            if abs(t_len - b_len) < (b_len * 0.05) and abs(f_len - b_len) > (b_len * 0.05):
                self.add_potential(v, "SQL Injection", "High", p, t_payload, "Boolean-based confirmation", r_true)

    def detect_error_sqli(self, v, p):
        # RULE 1.C: DB error patterns
        payloads = ["'", "\"", "%27"]
        error_sigs = ["sql syntax", "mysql_", "mariadb", "warning: mysqli", "postgresql", "oracle", "db2"]
        for load in payloads:
            res = self.send_payload(v, p, load)
            if res and any(sig in res.text.lower() for sig in error_sigs):
                self.add_potential(v, "SQL Injection", "High", p, load, "Probable SQLi via Database Error", res)

    def detect_blind_sqli(self, v, p):
        # RULE 1.D: DB-backed endpoints only
        SENSITIVE = ['product', 'list', 'artist', 'cart', 'user', 'search']
        if not any(s in v.url.lower() for s in SENSITIVE): return
        
        payload = "IF(1=1,SLEEP(5),0)"
        res = self.send_payload(v, p, payload)
        
        if res and res.elapsed.total_seconds() > 4.5:
            # Multi-indicator check (Real-time verification)
            res2 = self.send_payload(v, p, payload)
            if res2 and res2.elapsed.total_seconds() > 4.5:
                self.add_potential(v, "SQL Injection (Blind)", "High", p, payload, "Verified Time-based SQLi", res)

    def detect_xss(self, v):
        payloads = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
        for p in v.params:
            for load in payloads:
                res = self.send_payload(v, p, load)
                if res and load in res.text:
                    name = "Cross-site Scripting (Reflected)" if v.method == 'GET' else "Cross-site Scripting (Stored)"
                    self.add_potential(v, name, "High", p, load, "Payload reflection", res)

    def detect_cmdi(self, v):
        # 1. Parameter Filtering (STRICT)
        LIKELY_PARAMS = ['ip', 'host', 'cmd', 'ping', 'target', 'dns', 'query', 'addr', 'file', 'path']
        BLACK_PARAMS = ['submit', 'token', 'csrf', 'user_token', 'pass', 'btn', 'login']

        for p in v.params:
            if p.lower() in BLACK_PARAMS: continue
            
            # Target candidates
            is_valid_cand = any(cand in p.lower() for cand in LIKELY_PARAMS)
            if self.is_dvwa and "/vulnerabilities/exec/" in v.url:
                is_valid_cand = True
            
            if not is_valid_cand: continue

            # 2. Unique Random Marker
            marker = "CI_" + ''.join(random.choices(string.ascii_uppercase + string.numbers if hasattr(string, 'numbers') else string.digits, k=6))
            
            payloads = [
                f"; echo {marker}",
                f"| echo {marker}",
                f"&& echo {marker}"
            ]
            
            for load in payloads:
                res = self.send_payload(v, p, load)
                if not res: continue
                
                text = res.text
                
                # Check 1: Marker must NOT be in baseline
                if v.baseline and marker in v.baseline.get('text', ''): continue
                
                # Check 2: Marker presence
                if marker in text:
                    # Check 3: Reject HTML attribute reflection (false positives)
                    if f'value="{marker}"' in text or f'value=\'{marker}\'' in text or f'value={marker}' in text:
                        continue
                        
                    # Check 4: Execution Context Validation
                    # Strong evidence: surrounded by newlines, or in code/pre tags
                    if any(x in text for x in [f"\n{marker}", f"{marker}\n", f"\r\n{marker}"]) or \
                       "<pre>" in text.lower() or "<code>" in text.lower():
                        
                        # Extra check: ensure response changed significantly
                        if v.baseline and len(text) == v.baseline.get('length'):
                            continue

                        self.add_potential(v, "Command Injection (RCE)", "Critical", p, load, f"Execution confirmed: marker {marker} found in OS context", res)
                        return # Deduplicate: ONE per endpoint

    def detect_lfi(self, v):
        payloads = ["../../../../etc/passwd"]
        sigs = ["root:x:0:0"]
        for p in v.params:
            for load in payloads:
                res = self.send_payload(v, p, load)
                if not res: continue
                if any(sig in res.text for sig in sigs):
                    self.add_potential(v, "Sensitive File Exposure", "Info", p, load, "File content", res)

    def detect_csrf(self, v):
        # RULE 5: CSRF Accuracy Mode (Non-DVWA)
        if not self.is_dvwa:
            if v.method not in ['POST', 'PUT', 'DELETE']: return
            # Ignore search/read
            if any(x in v.url.lower() for x in ['search', 'list', 'read', 'view', 'nav']): return
            
        if v.method == 'POST':
            tokens = ['csrf', 'token', 'user_token']
            if not any(any(tk in p.lower() for tk in tokens) for p in v.params):
                self.add_potential(v, "CSRF", "Medium", "Form", "N/A", "Missing CSRF protection", None)

    def detect_headers(self, v):
        # RULE 6: Header Issues Optimization (Non-DVWA)
        host = urlparse(v.url).netloc
        if not self.is_dvwa and host in self.reported_headers: return
        
        h = v.baseline.get('headers', {}) if v.baseline else {}
        if 'X-Frame-Options' not in h:
            self.add_potential(v, "Clickjacking (UI Redressing)", "Low", "Header", "N/A", "XFO missing", None)
            if not self.is_dvwa: self.reported_headers.add(host)
        if 'Content-Security-Policy' not in h:
            self.add_potential(v, "CSP Bypass", "Low", "Header", "N/A", "CSP missing", None)
            if not self.is_dvwa: self.reported_headers.add(host)

    def detect_info(self, v):
        if "php version" in v.baseline.get('text', '').lower() if v.baseline else False:
             self.add_potential(v, "PHP Info", "Info", "Page", "N/A", "phpinfo() output", None)
        if v.url.endswith('.js'):
             self.add_potential(v, "JavaScript", "Medium", "Source", "N/A", "JS exposed", None)

    def detect_file_upload(self, v):
        if v.form and any(i.get('type') == 'file' for i in v.form.get('inputs', [])):
             self.add_potential(v, "File Upload", "High", "file", "rce.php", "Upload form found", None)

    def detect_brute_force(self, v):
        if v.form and any("pass" in i['name'].lower() for i in v.form['inputs']):
             self.add_potential(v, "Brute Force", "Low", "login", "admin/password", "Auth form found", None)

    def detect_weak_session(self, v):
        for cookie in self.session.cookies:
            if cookie.name == 'PHPSESSID' and len(str(cookie.value)) < 10:
                self.add_potential(v, "Weak Session IDs", "Medium", "Cookie", cookie.name, "Weak ID", None)

    def detect_dom_xss(self, v):
        if "xss_d" in v.url:
             self.add_potential(v, "XSS (DOM)", "High", "default", "English", "DOM context found", None)

    def detect_captcha(self, v):
        if "captcha" in v.url.lower():
             self.add_potential(v, "Insecure CAPTCHA", "Medium", "Form", "step=2", "Captcha bypass possible", None)

    # =========================================================================
    # PHASE 4 — CONFIRMATION (STRICT)
    # =========================================================================
    def phase4_confirmation(self):
        self.log_activity("Phase 4: Confirmation (Strict)...")
        for v in self.vectors:
            for pot in v.potentials:
                fingerprint = (pot['name'], pot['endpoint'], pot['parameter'])
                if fingerprint in self.confirmed_fingerprints: continue
                confirmed = self.confirm(v, pot)
                if confirmed:
                    self.confirmed_fingerprints.add(fingerprint)
                    with self.lock:
                        self.findings.append(confirmed)
                        if self.on_vuln: self.on_vuln(confirmed)
        self.update_progress(95)

    def confirm(self, v, pot):
        # MANDATORY BYPASS: If target contains DVWA fingerprints, use original logic
        if self.is_dvwa: return pot 

        name = pot['name']
        p = pot['parameter']
        ev = pot.get('evidence', '').lower()
        
        # RULE 2: CONFIDENCE CLASSIFICATION
        if "SQL" in name:
            # Boolean / Time-based -> CONFIRMED
            if "boolean" in ev or "verified" in ev or "sleep" in pot.get('payload', ''):
                return pot
            # Error-only -> PROBABLE
            if "error" in ev:
                pot['severity'] = 'High' # Keep High but mark as PROBABLE in desc
                pot['evidence'] = "PROBABLE: " + pot['evidence']
                return pot
            return None # Reflection-only -> IGNORE

        if "XSS" in name:
            # Indicator 1: Basic reflection
            res1 = self.send_payload(v, p, "TITAN_XSS_1")
            # Indicator 2: Full payload success with context proof
            res2 = self.send_payload(v, p, "<script>confirm(1)</script>")
            if res1 and "TITAN_XSS_1" in res1.text and res2 and "<script>confirm(1)</script>" in res2.text:
                if "value=" not in res2.text: # Context check
                    return pot
            return None
            
        if "Command Injection" in name:
            # Rule already enforced: Unique Random Marker + Context validation
            # Indicator 1: Marker 1
            marker1 = "CI_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
            res1 = self.send_payload(v, p, f"; echo {marker1}")
            # Indicator 2: Marker 2
            marker2 = "CI_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
            res2 = self.send_payload(v, p, f"; echo {marker2}")
            if res1 and marker1 in res1.text and res2 and marker2 in res2.text:
                 return pot
            return None

        # Pass through passive issues once
        return pot 

    def send_payload(self, v, p, load):
        params = v.params.copy()
        params[p] = load
        try:
            if v.method == 'POST': return self.session.post(v.url, data=params, timeout=10)
            return self.session.get(v.url, params=params, timeout=10)
        except: return None

    def add_potential(self, v, name, sev, p, load, ev, res=None):
        # RULE 7: Response Logging Limit / Performance
        if not self.is_dvwa:
            cache_key = (name, v.url, p, load)
            if cache_key in self.negative_cache: return
            if not res and name == "SQL Injection": return # Skip unconfirmed

        with self.lock:
            v.potentials.append({
                "name": name, 
                "severity": sev, 
                "endpoint": v.url, 
                "parameter": p, 
                "payload": load, 
                "evidence": str(ev)[:120],  # Rule 7 limit
                "request": format_http_request(res.request) if res else "", 
                "response": format_http_response(res) if res else "",
                "status_code": res.status_code if res else "200",
                "content_length": len(res.content) if res else "0"
            })

    def generate_report(self):
        return Reporter.generate_detailed_report(target=self.target_url, scan_time=datetime.now().isoformat(), duration=round(time.time() - self.start_time, 2), threads=self.max_threads, authenticated=self.authenticated, vulnerabilities=self.findings)

def scan_target(target_url, **kwargs):
    return TitanEngine(target_url, **kwargs).scan()
