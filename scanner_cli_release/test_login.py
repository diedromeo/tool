import requests
from bs4 import BeautifulSoup
import sys
import urllib3

urllib3.disable_warnings()

# Setup
target_url = "http://localhost/login.php"
config = {
    "login_url": "http://localhost/login.php",
    "method": "POST",
    "username_field": "username",
    "password_field": "password",
    "username": "admin",
    "password": "password",
    "success_indicator": "Logout",
    "cookies": {"security": "low"}
}

session = requests.Session()
session.verify = False
if config.get('cookies'):
    session.cookies.update(config['cookies'])
    print(f"[*] Set cookies: {session.cookies.get_dict()}")

try:
    print(f"[*] Fetching {target_url}...")
    resp = session.get(target_url, timeout=10)
    print(f"[*] Status: {resp.status_code}")
    print(f"[*] Final URL: {resp.url}")
    
    soup = BeautifulSoup(resp.text, 'html.parser')
    page_title = soup.title.string.strip() if soup.title else 'No Title'
    print(f"[*] Page Title: {page_title}")
    
    forms = soup.find_all('form')
    print(f"[*] Found {len(forms)} forms.")
    
    login_form = None
    for i, form in enumerate(forms):
        print(f"   Form {i} Action: {form.get('action')}")
        if form.find('input', {'name': config['password_field']}):
            login_form = form
            print(f"   [+] Identified hidden login form (Form {i})")
            break
            
    if not login_form and forms:
        print("   [!] Password field not found, using first form.")
        login_form = forms[0]
        
    hidden_data = {}
    if login_form:
        for input_tag in login_form.find_all('input'):
            name = input_tag.get('name')
            val = input_tag.get('value', '')
            if name:
                hidden_data[name] = val
                print(f"      Input: {name} = {val}")
    
    hidden_data[config['username_field']] = config['username']
    hidden_data[config['password_field']] = config['password']
    if 'Login' not in hidden_data:
        hidden_data['Login'] = 'Login'
        
    print(f"[*] POSTing data to {config['login_url']}: {hidden_data}")
    
    post_resp = session.post(config['login_url'], data=hidden_data, timeout=10)
    print(f"[*] Login Status: {post_resp.status_code}")
    print(f"[*] Login Final URL: {post_resp.url}")
    print(f"[*] Cookies after login: {session.cookies.get_dict()}")
    
    if config['success_indicator'] in post_resp.text:
        print("[+] SUCCESS: Found success indicator!")
    else:
        print("[-] FAILURE: Success indicator NOT found.")
        print("    Response Snippet (first 500 chars):")
        print(post_resp.text[:500])
        
except Exception as e:
    print(f"[!] Exception: {e}")
