
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
    """Formats a requests.Response object into an HTTP response string."""
    if not response: return ""
    try:
        # Reconstruct status line
        status_line = f"HTTP/1.1 {response.status_code} {response.reason}"
        headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        body = response.text[:10000] if response.text else ""
        return f"{status_line}\n{headers}\n\n{body}"
    except Exception:
        return str(response)
