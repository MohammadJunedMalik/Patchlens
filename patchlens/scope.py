from urllib.parse import urlparse, urljoin

class Scope:
    def __init__(self, target_url: str):
        t_u = target_url.strip()
        parsed = urlparse(t_u)
        self.scheme = parsed.scheme.lower()
        self.host = parsed.netloc.lower()
        if self.scheme not in ("http", "https") :
            raise ValueError("Target URl should starts with 'http://' or 'https://'.")
        if not self.host:
            raise ValueError("Target URL shoul have an valid domain or IP.")
        
    def normalize(self, base_url: str, link: str):
        clean_b = base_url.strip()
        clean_l = link.strip()
        joined_url = urljoin(clean_b,clean_l).split('#')[0]

        return joined_url

    def in_scope(self, candidate_url: str) :

        if not candidate_url :
            return False    
        
        clean_cu = candidate_url.strip().lower()
        if clean_cu.startswith(('mailto:','javascript:','tel:')):
            return False

        parsed =  urlparse(clean_cu)
        netloc = parsed.netloc.lower()

        if not netloc:
            return True

        return netloc == self.host 


    