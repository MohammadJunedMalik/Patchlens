# i have imported python module  requests for sending http requests to server 
#  requests.exception used if any error arises like timeout, DNS failures , low connection ..etc. 
import requests 
from requests.exceptions import RequestException


class SafeHttp:
    # in this init function ,i have taken an instance of our Scope class , set default time to 5 seconds and stopping infinite redirect loops by settings int to 5.
    # created an empty list to store skipped urls and it's reason for skipping that url
    def __init__(self, scope: str, timeout: float = 5.0, max_redirect: int = 5):
        self.scope = scope
        self.timeout = timeout
        self.max_redirect = max_redirect
        self.skipped: list[dict] = []
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Patchlens/1.0 +Security Scannner"
    
    
    # in this get function is used to check and decide it is safe or not while redirecting a url if it goes to some malicious website 
    # and if error appear  url and with it's reason will go to the list created in above function 
    def get(self, url: str):
        if not self.scope.in_scope(url):
            self.skipped.append({"url": url, "reason": "out of scope"})
            return None
        current_u = url
        count = 0

        while count <= self.max_redirect:
            try:
                response = self.session.get(current_u, timeout = self.timeout, allow_redirects = False)
                tple = (301,302,303,307,308)
                
                if response.status_code in tple :
                    location = response.headers.get("Location")
                    if not location:
                        return response
                
                    next_u = self.scope.normalize(current_u, location)
                    if not self.scope.in_scope(next_u):
                        self.skipped.append({"url" : next_u, "reason": "Redirected out of scope"})
                        return None
                
                    current_u = next_u
                    count += 1
                    continue
                return response

            except RequestException as e :
                self.skipped.append({"url": current_u , "reason" : str(e)})
                return None

        if count > self.max_redirect:
            self.skipped.append({"url": url, "reason": "Exceeded maximum redirect limit"})
            return None


        
    