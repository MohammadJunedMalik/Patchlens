from patchlens.scope import Scope
from patchlens.http_client import SafeHttp
from patchlens.crawler import Crawler
from patchlens.findings import Finding
from patchlens.checks.cookies import Cookiechecker
from patchlens.checks.headers import Headerchecker
from patchlens.checks.mixed import Mixedcontentchecker
from patchlens.checks.tls import Tlschecker
from patchlens.historydb import Historydatabase

class Scanengine:
    def __init__(self,max_pages: int = 10, max_depth: int = 2, timeout: float = 5.0):     
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.tls = Tlschecker()
        self.mix = Mixedcontentchecker()
        self.cookie = Cookiechecker()
        self.header = Headerchecker()
        self.history = Historydatabase()

    def scan(self, target_url: str) -> list[Finding]:
        findings: list[Finding] = []
        scope = Scope(target_url)
        client = SafeHttp(scope, timeout= self.timeout)
        tls = self.tls.check_all(target_url)
        findings.extend(tls)
        crawler = Crawler(client, max_pages = self.max_pages, max_depth = self.max_depth)
        crawl = crawler.crawl(target_url)
        for c in crawl:
            mix = self.mix.check_all(c.url, c.text)
            cookie = self.cookie.check_all(c.url, c.headers)
            header = self.header.check_all(c.url, c.headers)

            findings.extend(mix)
            findings.extend(cookie)
            findings.extend(header)

        unique_f: list[Finding] = []
        
        seen: set[str] = set()
        for f in findings :
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique_f.append(f)
        
        
        his = self.history.scan_verification(target_url, unique_f)
        verify_f = self.history.scan_save(target_url, his)
        return his
        
    


    