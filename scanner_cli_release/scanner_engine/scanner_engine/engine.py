
import requests
import time
import logging
import urllib3
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from scanner_engine.crawler import Crawler
from scanner_engine.scanners.xss_scanner import XSSScanner
from scanner_engine.scanners.sqli import SQLIScanner
from scanner_engine.scanners.csrf import CSRFScanner
from scanner_engine.scanners.open_redirect import RedirectScanner
from scanner_engine.scanners.idor import IDORScanner
from scanner_engine.scanners.auth_weakness import AuthWeaknessScanner
from scanner_engine.scanners.clickjacking import ClickjackingScanner
from scanner_engine.scanners.cors import CORSScanner
from scanner_engine.scanners.header_scanner import HeaderScanner
from scanner_engine.scanners.info_disclosure import InfoDisclosureScanner


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def scan_target(target_url: str, authenticated: bool = False, auth_config: dict | None = None, status_checker=None, on_activity=None, on_progress=None, on_vuln=None, max_threads: int = 10) -> dict:
    """
    Main entry point for the scanner. Fully compliant with Section 3, 4, and 5 requirements.
    """
    def check_pause_terminate():
        if status_checker:
            while True:
                status = status_checker()
                if status == 'Terminated':
                    raise InterruptedError("Scan Terminated")
                if status == 'Paused':
                    time.sleep(1)
                else:
                    break

    if on_progress: on_progress(5)
    start_time = time.time()
    session = requests.Session()
    # Increase connection pool size to match threads
    adapter = requests.adapters.HTTPAdapter(pool_connections=max_threads, pool_maxsize=max_threads)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False # Ignore SSL errors
    all_vulnerabilities = []
    
    check_pause_terminate()

    # -------------------------------------------------------------------------
    # 0. Initial Connectivity & Redirection Resolution (Sec 6.0)
    # We resolve the final URL before starting any scans to ensure we are scanning
    # the correct scope (e.g. handling HTTP -> HTTPS redirects, or www -> non-www).
    # -------------------------------------------------------------------------
    try:
        if on_activity: on_activity(f"Validating target & resolving redirects: {target_url}")
        # Use stream=True to get headers only without downloading body yet
        # We also use a browser-like User-Agent to avoid being blocked immediately
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        initial_resp = session.get(target_url, headers=headers, timeout=20, allow_redirects=True, stream=True)
        
        final_url = initial_resp.url
        initial_resp.close() # Close connection
        
        # If the URL changed effectively (protocol or domain change)
        if final_url != target_url:
            logger.info(f"Target redirected: {target_url} -> {final_url}")
            if on_activity: on_activity(f"Target redirected to: {final_url}")
            target_url = final_url 
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Initial connection failed for {target_url}: {e}")
        if on_activity: on_activity(f"Warning: Initial connection failed ({str(e)}). Attempting to proceed anyway...")
        # We don't hard fail here to allow edge cases, but it's a strong indicator of issues.
        
    
    def handle_new_vuln(vuln):
        all_vulnerabilities.append(vuln)
        if on_vuln:
            on_vuln(vuln)
    
    # 4.4 Session Fixation & Authenticated Scan (Section B)
    if authenticated and auth_config:
        try:
            # 1. Active Session Fixation Probe (Client-Side)
            # We explicitly set a session cookie. If the server accepts it and keeps it after login, it's vulnerable.
            fixation_id = "ScannerTestFixation123"
            
            # Create a dedicated session for the fixation test to not pollute the main authenticated session
            fix_session = requests.Session()
            fix_session.verify = False
            fix_session.cookies.set('PHPSESSID', fixation_id)
            fix_session.cookies.set('JSESSIONID', fixation_id)
            fix_session.cookies.set('ASP.NET_SessionId', fixation_id)

            logger.info(f"Probing Session Fixation on {auth_config['login_url']} with ID {fixation_id}")
            if on_activity: on_activity(f"Probing Session Fixation...")
            
            try:
                # Login with the fixed session ID
                login_data = {
                    auth_config['username_field']: auth_config['username'],
                    auth_config['password_field']: auth_config['password']
                }
                resp = fix_session.post(auth_config['login_url'], data=login_data, timeout=10)
                
                # Check cookies AFTER login
                post_cookies = fix_session.cookies.get_dict()
                
                # Check if our injected ID is still there
                # Note: requests.Session might update the cookie jar if the server sends a Set-Cookie
                # If the server does NOT send Set-Cookie, the original holds.
                # If the server sends Set-Cookie with the SAME value, it holds.
                # If the server sends Set-Cookie with NEW value, it's secure.
                
                final_phpsess = post_cookies.get('PHPSESSID')
                final_jsess = post_cookies.get('JSESSIONID')
                final_aspxsess = post_cookies.get('ASP.NET_SessionId')
                
                is_fixed = False
                if final_phpsess == fixation_id: is_fixed = True
                if final_jsess == fixation_id: is_fixed = True
                if final_aspxsess == fixation_id: is_fixed = True
                
                if is_fixed:
                     # Helper for formatting
                     def fmt_req(r):
                        if not r: return ""
                        h = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
                        b = r.body if r.body else "" 
                        if isinstance(b, bytes):
                            try: b = b.decode('utf-8', errors='ignore')
                            except: b = "<binary>"
                        return f"{r.method} {r.url}\n{h}\n\n{b}"
                     
                     def fmt_res(r):
                        if not r: return ""
                        h = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
                        t = r.text[:5000]
                        return f"HTTP/1.1 {r.status_code}\n{h}\n\n{t}"

                     handle_new_vuln({
                        "name": "Session Fixation",
                        "severity": "Medium",
                        "endpoint": auth_config['login_url'],
                        "parameter": "PHPSESSID/JSESSIONID/ASP.NET_SessionId",
                        "payload": fixation_id,
                        "evidence": f"Server accepted and maintained the injected session ID '{fixation_id}' after login.",
                        "action_url": auth_config['login_url'],
                        "http_method": "POST",
                        "input_field_name": "Cookie: Session ID",
                        "request": fmt_req(resp.request),
                        "response": fmt_res(resp)
                    })
                else:
                    logger.info("Session Fixation Probe: Secure (ID rotated or ignored).")

            except Exception as e:
                logger.error(f"Session Fixation Probe Failed: {e}")
            
            # 2. Main Authenticated Session (Standard Login)
            logger.info(f"Authenticating main session to {auth_config['login_url']}")
            
            main_login_data = {
                auth_config.get('username_field', 'username'): auth_config['username'],
                auth_config.get('password_field', 'password'): auth_config['password']
            }
            
            method = auth_config.get('method', 'POST').upper()
            if method == 'POST':
                resp = session.post(auth_config['login_url'], data=main_login_data, timeout=10)
            else:
                resp = session.get(auth_config['login_url'], params=main_login_data, timeout=10)
            
            # Verify Login Success
            success_indicator = auth_config.get('success_indicator')
            if success_indicator and success_indicator not in resp.text:
                if on_activity: on_activity(f"Authentication Failed: Indicator '{success_indicator}' not found.")
                logger.error(f"Authentication verification failed. '{success_indicator}' not found in response.")
                # We do not abort, but warning is critical
            elif success_indicator:
                if on_activity: on_activity(f"Authentication Successful (Verified by '{success_indicator}')")
                logger.info("Authentication verified successfully.")

            # 5.1 Auth Weakness Probe (MUST USE FRESH SESSION)
            weakness_session = requests.Session()
            weakness_session.verify = False 
            auth_scanner = AuthWeaknessScanner(session=weakness_session, on_vuln=handle_new_vuln)
            
            # only run if fields are standard/provided, might need update for config flexibility, 
            # but keeping basic for now as it relies on specific field names
            auth_scanner.check_brute_force_protection(
                auth_config['login_url'], 
                auth_config.get('username_field', 'username'), 
                auth_config.get('password_field', 'password')
            )
            all_vulnerabilities.extend(auth_scanner.get_results())

            logger.info("Authentication session established.")
            
        except Exception as e:
            logger.error(f"Login failure: {e}")
            return {"error": "Authentication Aborted", "details": str(e)}

    if on_progress: on_progress(10)
    last_p = 10

    def report_fine(start, end, cur, tot):
        nonlocal last_p
        if tot <= 0: return
        p = int(start + (end - start) * (cur / tot))
        if p > last_p:
            if on_progress: on_progress(p)
            last_p = p



    # Phase 1: Crawling (Sec 6.1)
    logger.info(f"Starting crawler on {target_url}")
    if on_activity: on_activity(f"Initializing Crawler on {target_url}")
    crawler = Crawler(target_url, session=session, max_pages=300)
    
    orig_parse = crawler._parse_content
    urls_found = 0
    def patched_parse(url, html, is_json=False):
        nonlocal urls_found, last_p
        urls_found += 1
        link_type = "JSON API" if is_json else "deep link"
        if on_activity: on_activity(f"Spidering {link_type}: {url}")
        p = min(10 + (urls_found // 2), 39)
        if p > last_p:
            if on_progress: on_progress(p)
            last_p = p


        return orig_parse(url, html, is_json=is_json)
    
    crawler._parse_content = patched_parse
    
    crawl_results = crawler.crawl()
    discovered_urls = crawl_results['urls']
    discovered_forms = crawl_results['forms']
    
    if on_progress: on_progress(40)
    last_p = 40
    check_pause_terminate()

    MAX_WORKERS = max_threads 

    # Phase 2: Scanning
    
    # 1. XSS Audit (Concurrent)
    if on_activity: on_activity("Launching Concurrent XSS Audit Engine...")
    xss_scanner = XSSScanner(session=session, on_vuln=handle_new_vuln)
    total_xss_tasks = len(discovered_urls) + len(discovered_forms)
    
    def scan_xss_wrapper(url):
        if on_activity: on_activity(f"Testing XSS on: {url}")
        xss_scanner.scan_url(url)
        
    def scan_xss_form_wrapper(form):
        action = form.get('action', 'Unknown Form')
        if on_activity: on_activity(f"Testing XSS on Form: {action}")
        xss_scanner.scan_form(form)

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for url in discovered_urls:
                futures.append(executor.submit(scan_xss_wrapper, url))
            for form in discovered_forms:
                futures.append(executor.submit(scan_xss_form_wrapper, form))
                
            for i, future in enumerate(as_completed(futures)):
                check_pause_terminate()
                report_fine(40, 55, i, total_xss_tasks)
    except Exception as e:
        logger.error(f"XSS Scan Error: {e}")
            
    # xss_scanner.scan_forms(discovered_forms) # Handled concurrently above
    all_vulnerabilities.extend(xss_scanner.get_results())

    # 2. SQLi Audit (Concurrent)
    if on_activity: on_activity("Launching Concurrent SQLi Heuristic Nodes...")
    sqli_scanner = SQLIScanner(session=session, on_vuln=handle_new_vuln)
    total_sqli_tasks = len(discovered_urls) + len(discovered_forms)
    
    def scan_sqli_wrapper(url):
        if on_activity: on_activity(f"Testing SQLi on: {url}")
        sqli_scanner.scan_url(url)
        
    def scan_sqli_form_wrapper(form):
        action = form.get('action', 'Unknown Form')
        if on_activity: on_activity(f"Testing SQLi on Form: {action}")
        sqli_scanner.scan_form(form)
        
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for url in discovered_urls:
                futures.append(executor.submit(scan_sqli_wrapper, url))
            for form in discovered_forms:
                futures.append(executor.submit(scan_sqli_form_wrapper, form))
                
            for i, future in enumerate(as_completed(futures)):
                check_pause_terminate()
                report_fine(55, 75, i, total_sqli_tasks)
    except Exception as e:
        logger.error(f"SQLi Scan Error: {e}")
        
    # sqli_scanner.scan_forms(discovered_forms) # Handled concurrently above
    all_vulnerabilities.extend(sqli_scanner.get_results())

    # 3. IDOR, Redirects, Clickjacking, CORS, & Header Audits
    if on_activity: on_activity("Evaluating Header-based Security & Access Controls...")
    redirect_scanner = RedirectScanner(session=session, on_vuln=handle_new_vuln)
    idor_scanner = IDORScanner(session=session, on_vuln=handle_new_vuln)
    cj_scanner = ClickjackingScanner(session=session, on_vuln=handle_new_vuln)
    cors_scanner = CORSScanner(session=session, on_vuln=handle_new_vuln)
    header_scanner = HeaderScanner(session=session, on_vuln=handle_new_vuln)
    
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for url in discovered_urls:
                executor.submit(redirect_scanner.scan_url, url)
                executor.submit(idor_scanner.scan_url, url)
                executor.submit(cj_scanner.scan_url, url)
                executor.submit(cors_scanner.scan_url, url)
                executor.submit(header_scanner.scan_url, url)
    except Exception as e:
         logger.error(f"Audit Phase Error: {e}")
            
    all_vulnerabilities.extend(redirect_scanner.get_results())
    all_vulnerabilities.extend(idor_scanner.get_results())
    all_vulnerabilities.extend(cj_scanner.get_results())
    all_vulnerabilities.extend(cors_scanner.get_results())
    all_vulnerabilities.extend(header_scanner.get_results())

    # 4. Sensitive File Exposure (Info Disclosure)
    if on_activity: on_activity("Scanning for Common Sensitive Files (.env, .git, etc.)...")
    info_scanner = InfoDisclosureScanner(session=session, on_vuln=handle_new_vuln)
    
    # We only scan the base domain/path for these files, not every crawled URL
    # Assuming target_url is the base
    info_scanner.scan_url(target_url) 
    all_vulnerabilities.extend(info_scanner.get_results())

    # 4. CSRF Evaluation
    if on_activity: on_activity("Evaluating CSRF protection mechanisms...")
    csrf_scanner = CSRFScanner(session=session, on_vuln=handle_new_vuln)
    csrf_scanner.scan_forms(discovered_forms)
    all_vulnerabilities.extend(csrf_scanner.get_results())
    
    if on_progress: on_progress(95)
    duration = time.time() - start_time
    
    # Final Result Format (Sec 7)
    return {
        "target": target_url,
        "scan_type": "authenticated" if authenticated else "non-authenticated",
        "vulnerabilities": all_vulnerabilities,
        "scan_duration_seconds": round(duration, 2),
        "urls_scanned": len(discovered_urls),
        "forms_scanned": len(discovered_forms)
    }
