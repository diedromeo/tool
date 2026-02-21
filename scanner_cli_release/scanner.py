#!/usr/bin/env python3
import argparse
import json
import sys
import os
import time
from datetime import datetime

# We will try to import colorama, but if it fails (dev environment), we can fallback or just suggest installing it.
# To ensure consistency with the release, we'll suggest installing it if missing.
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
except ImportError:
    print("Warning: colorama not found. Install it with 'pip install colorama' for colored output.")
    class Fore:
        RED = ""
        GREEN = ""
        YELLOW = ""
        BLUE = ""
        CYAN = ""
        MAGENTA = ""
        WHITE = ""
    class Style:
        BRIGHT = ""
        RESET_ALL = ""

# -------------------------------------------------------------------------
# Dynamic Path Configuration
# -------------------------------------------------------------------------
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

try:
    from scanner_engine.engine import scan_target
except ImportError as e:
    print(Fore.RED + f"[!] Error importing scanner engine: {e}")
    sys.exit(1)

# -------------------------------------------------------------------------
# Configuration & Constants
# -------------------------------------------------------------------------

OWASP_MAP = {
    "XSS": "https://owasp.org/www-community/attacks/xss/",
    "Reflected XSS": "https://owasp.org/www-community/attacks/xss/",
    "Stored XSS": "https://owasp.org/www-community/attacks/xss/",
    "DOM-based XSS": "https://owasp.org/www-community/attacks/dom-based-xss/",
    "SQL Injection": "https://owasp.org/www-community/attacks/SQL_Injection",
    "SQLi": "https://owasp.org/www-community/attacks/SQL_Injection",
    "Blind SQLi": "https://owasp.org/www-community/attacks/SQL_Injection",
    "CSRF": "https://owasp.org/www-community/attacks/csrf",
    "IDOR": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
    "Open Redirect": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/04-Testing_for_Client-Side_URL_Redirect",
    "Clickjacking": "https://owasp.org/www-community/attacks/Clickjacking",
    "CORS Misconfiguration": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
    "Missing Security Header": "https://owasp.org/www-project-secure-headers/",
    "Auth Weakness": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
    "Session Fixation": "https://owasp.org/www-community/attacks/Session_Fixation"
}

OWASP_ID_MAP = {
    "XSS": "A03:2021-Injection",
    "Reflected XSS": "A03:2021-Injection",
    "Stored XSS": "A03:2021-Injection",
    "DOM-based XSS": "A03:2021-Injection",
    "SQL Injection": "A03:2021-Injection",
    "SQLi": "A03:2021-Injection",
    "Blind SQLi": "A03:2021-Injection",
    "CSRF": "A01:2021-Broken Access Control",
    "IDOR": "A01:2021-Broken Access Control",
    "Open Redirect": "A01:2021-Broken Access Control",
    "Clickjacking": "A05:2021-Security Misconfiguration",
    "CORS Misconfiguration": "A05:2021-Security Misconfiguration",
    "Missing Security Header": "A05:2021-Security Misconfiguration",
    "Auth Weakness": "A07:2021-Identification and Authentication Failures",
    "Session Fixation": "A07:2021-Identification and Authentication Failures"
}

def get_owasp_link(vuln_name):
    for key, link in OWASP_MAP.items():
        if key.lower() in vuln_name.lower():
            return link
    return "https://owasp.org/www-project-top-ten/"

def get_owasp_id(vuln_name):
    for key, owasp_id in OWASP_ID_MAP.items():
        if key.lower() in vuln_name.lower():
            return owasp_id
    return "N/A"

def print_banner():
    banner = f"""
    {Fore.CYAN}=======================================================
       ADVANCED VULNERABILITY SCANNER CLI (Real-Time)
    ======================================================={Style.RESET_ALL}
    """
    print(banner)

def get_severity_color(severity):
    severity = severity.lower()
    if "critical" in severity:
        return Fore.RED + Style.BRIGHT
    elif "high" in severity:
        return Fore.RED
    elif "medium" in severity:
        return Fore.YELLOW
    elif "low" in severity:
        return Fore.GREEN
    else:
        return Fore.BLUE

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Web Vulnerability Scanner CLI Tool",
        usage="%(prog)s [options] -u <url>",
        epilog="Example: python cli.py -u http://testphp.vulnweb.com -t 20 -o report.json"
    )
    
    parser.add_argument("-u", "--url", help="Target URL to scan", required=True)
    parser.add_argument("-t", "--threads", help="Number of concurrent threads (default: 10)", type=int, default=10)
    parser.add_argument("-o", "--output", help="Output JSON file path (default: scan_result_<timestamp>.json)", type=str)
    
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument("--auth-user", help="Username for authenticated scan", type=str)
    auth_group.add_argument("--auth-pass", help="Password for authenticated scan", type=str)
    auth_group.add_argument("--login-url", help="Login URL for authenticated scan", type=str)
    auth_group.add_argument("--config", help="Path to configuration JSON file (contains auth details)", type=str)
    
    args = parser.parse_args()
    
    print_banner()
    
    target_url = args.url
    threads = args.threads
    
    auth_config = None
    authenticated = False
    
    cookies = None

    if args.config:
        try:
            with open(args.config, 'r') as f:
                config_data = json.load(f)
                
            # If URL is not provided in CLI, try to get it from config (optional feature)
            # But CLI url usually overrides.
            
            if 'username' in config_data and 'password' in config_data and 'login_url' in config_data:
                print(Fore.GREEN + f"[*] Loaded configuration from {args.config}")
                authenticated = True
                auth_config = config_data
            
            if 'cookies' in config_data:
                cookies = config_data['cookies']
                print(Fore.GREEN + f"[*] Loaded custom cookies: {cookies}")

        except Exception as e:
            print(Fore.RED + f"[!] Error loading config file: {e}")
            sys.exit(1)

    elif any([args.auth_user, args.auth_pass, args.login_url]) and not all([args.auth_user, args.auth_pass, args.login_url]):
        print(Fore.RED + "[!] Error: To use authentication, you must provide --auth-user, --auth-pass, AND --login-url.")
        sys.exit(1)

    elif args.auth_user and args.auth_pass and args.login_url:
        print(Fore.GREEN + f"[*] Authenticated scan configured for user: {args.auth_user}")
        authenticated = True
        auth_config = {
            "username": args.auth_user,
            "password": args.auth_pass,
            "login_url": args.login_url,
            "username_field": "username", 
            "password_field": "password"
        }
    
    
    print(Fore.CYAN + f"[*] Starting scan on: {target_url}")
    print(Fore.CYAN + f"[*] Thread count: {threads}")
    print(Fore.CYAN + "[*] Real-time scanning started... Findings will appear below:\n")
    
    # -------------------------------------------------------------------------
    # Callbacks
    # -------------------------------------------------------------------------
    def on_vuln(vuln):
        sev = vuln.get('severity', 'Info')
        color = get_severity_color(sev)
        name = vuln.get('name', 'Unknown')
        url = vuln.get('endpoint', '')
        param = vuln.get('parameter', '')
        payload = vuln.get('payload', 'N/A')
        
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Main Vulnerability Line
            msg = f"{Fore.WHITE}[{timestamp}] {color}[{sev.upper()}] {Fore.WHITE}{name} found at {Fore.CYAN}{url}"
            sys.stdout.write("\r" + " " * 80 + "\r")
            
            # Sanitization for Windows Console
            try:
                print(msg)
            except UnicodeEncodeError:
                print(msg.encode('ascii', 'ignore').decode('ascii'))
            
            # Details Line (Payload & PoC)
            details = ""
            if param:
                details += f"    {Fore.MAGENTA}npm -- Parameter: {Fore.WHITE}{param}\n"
            if payload and payload != 'N/A':
                details += f"    {Fore.MAGENTA}npm -- Payload: {Fore.YELLOW}{payload}\n"
                
            # Construct PoC if possible (Simple GET approximation)
            if param and payload and payload != 'N/A':
                # rudimentary check if it's already a query string
                separator = "&" if "?" in url else "?"
                poc_url = f"{url}{separator}{param}={payload}"
                details += f"    {Fore.MAGENTA}npm -- PoC URL: {Fore.BLUE}{Style.BRIGHT}{poc_url}\n"
            else:
                 details += f"    {Fore.MAGENTA}npm -- Evidence: {Fore.WHITE}{vuln.get('evidence', 'See report')}\n"

            try:
                print(details)
            except UnicodeEncodeError:
                print(details.encode('ascii', 'ignore').decode('ascii'))
                
        except Exception as e:
            # Fallback simple print if formatting fails
             print(f"[!] Vulnerability found: {name} at {url} (Formatting Error: {e})")
        
    def on_progress(p):
        sys.stdout.write(f"\r{Fore.BLUE}[*] Progress: {p}%...{Style.RESET_ALL}")
        sys.stdout.flush()
        
    def on_activity(msg):
        pass
        
    try:
        results = scan_target(
            target_url, 
            authenticated=authenticated, 
            auth_config=auth_config,
            on_progress=on_progress,
            on_activity=on_activity,
            on_vuln=on_vuln,
            max_threads=threads,
            cookies=cookies
        )
        sys.stdout.write("\r" + " " * 80 + "\r")
        print(Fore.GREEN + "\n[*] Scan completed!")
        
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"\n[!] An error occurred: {str(e)}")
        sys.exit(1)
        
    # The engine now returns the fully formatted report as per strict requirements
    final_output = results
    
    # We still need to print the summary to the console for the user
    severity_counts = final_output.get("severity_summary", {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0
    })
    enriched_vulns = final_output.get("vulnerabilities", [])
    
    if args.output:
        outfile = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        outfile = f"scan_result_{timestamp}.json"
        
    with open(outfile, "w") as f:
        json.dump(final_output, f, indent=4)
        
    print(Fore.CYAN + f"[*] Results saved to: {os.path.abspath(outfile)}")
    print(Fore.WHITE + f"[*] Total Vulnerabilities Found: {len(enriched_vulns)}")
    print(Fore.RED + Style.BRIGHT + "    - Critical: ", severity_counts.get("Critical", 0))
    print(Fore.RED + "    - High:     ", severity_counts.get("High", 0))
    print(Fore.YELLOW + "    - Medium:   ", severity_counts.get("Medium", 0))
    print(Fore.GREEN + "    - Low:      ", severity_counts.get("Low", 0))

if __name__ == "__main__":
    main()
