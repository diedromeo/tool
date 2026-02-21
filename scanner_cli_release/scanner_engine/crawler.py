import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

class Crawler:
    def __init__(self, target_url, session=None, max_pages=50, max_workers=5):
        self.start_url = target_url
        self.session = session if session else requests.Session()
        self.visited = set()
        self.discovered_urls = set()
        self.forms = []
        self.scope_domain = urlparse(target_url).netloc
        self.max_pages = max_pages
        self.max_workers = max_workers
        self.lock = threading.Lock()
        self.queue = [target_url]

    def crawl(self):
        logging.info(f"Starting concurrent crawl on {self.start_url}")
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                while self.queue and len(self.visited) < self.max_pages:
                    current_batch = []
                    while self.queue and len(current_batch) < self.max_workers:
                        url = self.queue.pop(0)
                        if url not in self.visited:
                            current_batch.append(url)
                    
                    if not current_batch:
                        break
                        
                    try:
                        futures = [executor.submit(self._fetch_and_parse, url) for url in current_batch]
                        for future in futures:
                            try:
                                future.result() 
                            except Exception as e:
                                logging.error(f"Concurrency error: {e}")
                    except RuntimeError as e:
                        logging.error(f"Executor Error (Crawl Stopping): {e}")
                        break
        except Exception as e:
             logging.error(f"Critical Crawl Error: {e}")

        return {
            "urls": list(self.visited),
            "forms": self.forms
        }

    def _fetch_and_parse(self, url):
        with self.lock:
            if url in self.visited or len(self.visited) >= self.max_pages:
                return
            self.visited.add(url)

        try:
            response = self.session.get(url, timeout=5, allow_redirects=True)
            ct = response.headers.get('Content-Type', '').lower()
            if response.status_code == 200:
                if 'application/json' in ct:
                    self._parse_content(url, response.text, is_json=True)
                elif 'text/html' in ct:
                    # Use response.url to resolve relative links correctly against redirects
                    self._parse_content(response.url, response.text, is_json=False)
        except Exception as e:
            logging.error(f"Fetch error for {url}: {e}")

    def _parse_content(self, current_url, html, is_json=False):
        import re
        # Improved regex to capture full URLs including parameters
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        
        if is_json:
            # JSON Discovery
            json_urls = re.findall(url_pattern, html)
            for j_url in json_urls:
                # Basic cleanup
                j_url = j_url.strip(").,;'\"")
                
                # Auto-add scheme for www. links found in text
                if j_url.startswith('www.') and '://' not in j_url:
                    scheme = urlparse(current_url).scheme or 'http'
                    j_url = f"{scheme}://{j_url}"

                parsed_url = urlparse(j_url)
                if parsed_url.netloc == self.scope_domain or not parsed_url.netloc:
                     # Handle relative URLs found in JSON if possible (rare but happens)
                     if not parsed_url.netloc:
                         j_url = urljoin(current_url, j_url)
                         parsed_url = urlparse(j_url)
                         
                     if parsed_url.netloc == self.scope_domain:
                        with self.lock:
                            if j_url not in self.visited and j_url not in self.queue:
                                self.queue.append(j_url)
                                self.discovered_urls.add(j_url)
            return

        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract Links from Anchor Tags
        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(current_url, link['href'])
            parsed_url = urlparse(absolute_url)
            
            if parsed_url.netloc == self.scope_domain:
                clean_url = absolute_url.split('#')[0]
                with self.lock:
                    if clean_url not in self.visited and clean_url not in self.queue:
                        self.queue.append(clean_url)
                        self.discovered_urls.add(clean_url)

        # Extract Forms
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'GET').upper()
            absolute_action = urljoin(current_url, action).split('#')[0] if action else current_url.split('#')[0]
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    inputs.append({"name": input_name, "type": input_type})
            
            with self.lock:
                self.forms.append({
                    "url": current_url,
                    "action": absolute_action,
                    "method": method,
                    "inputs": inputs
                })

        # Regex Fallback for HTML (to catch links in scripts/comments)
        text_urls = re.findall(url_pattern, html)
        for t_url in text_urls:
            t_url = t_url.strip(").,;'\"")
            
            # Auto-add scheme for www. links found in text
            if t_url.startswith('www.') and '://' not in t_url:
                scheme = urlparse(current_url).scheme or 'http'
                t_url = f"{scheme}://{t_url}"
                
            # Handle absolute links found via regex
            parsed_url = urlparse(t_url)
            if parsed_url.netloc == self.scope_domain:
                with self.lock:
                    if t_url not in self.visited and t_url not in self.queue:
                        self.queue.append(t_url)
                        self.discovered_urls.add(t_url)
