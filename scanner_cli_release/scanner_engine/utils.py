
def format_http_request(request):
    """Formats a requests.PreparedRequest object into an HTTP request string."""
    if not request: return ""
    headers = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
    body = request.body if request.body else ""
    if isinstance(body, bytes):
        try: body = body.decode('utf-8', errors='ignore')
        except: body = "<binary data>"
    elif not isinstance(body, str):
        body = str(body)
        
    return f"{request.method} {request.url}\n{headers}\n\n{body}"


def format_http_response(response):
    """Normalized response formatter. Max 120 chars. No HTML body."""
    if not response: return ""
    import re
    
    try:
        status_line = f"HTTP/1.1 {response.status_code}"
        body = response.text if response.text else ""
        lower_body = body.lower()
        
        # Rule 3: Text-based proof detection
        evidence_markers = [
            "sql syntax", "mysql_", "pdo exception", "mysqli_", 
            "titan_", "vuln_check", "root:x:0:0", "[extensions]",
            "error:", "warning:", "at line", "alert(", "prompt("
        ]
        
        found_ev = None
        for m in evidence_markers:
            if m in lower_body:
                idx = lower_body.find(m)
                # Take 60 chars of context
                snippet = body[idx:idx+60].replace('\n', ' ').replace('\r', ' ').strip()
                # Absolute Constraint: Strip HTML and hide sensitive tags
                snippet = re.sub(r'<[^>]+>', '', snippet) # Remove tags
                if any(tag in snippet.lower() for tag in ['<html>', '<script>', '<body>', '<img', '<svg']):
                    snippet = "Text-based evidence found (HTML contents hidden)"
                found_ev = snippet
                break
        
        if found_ev:
            # Rule 3 format
            res = f"{status_line} | Evidence: {found_ev[:60]}"
        else:
            # Rule 1 & 2 format
            cl = response.headers.get('Content-Length')
            if cl:
                res = f"{status_line} | Content-Length: {cl}"
            else:
                l = len(body)
                res = f"{status_line} | Response size approx: {l}"
        
        return res[:120]
    except Exception:
        # Fail-safe minimal response
        return f"HTTP/1.1 {getattr(response, 'status_code', '???')} | Response unparseable"
