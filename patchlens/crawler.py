# we have imported deque for fast and high performance in the code that work fast in o(1) containers
# imported beautifulsoup from collections for to make html from unstructed date  to structured searchable tree
from collections import deque
from bs4 import BeautifulSoup
class Crawler:
    # created an empty set for tracking visited urls and created parameters
    def __init__(self, http_client: str, max_pages: int = 25, max_depth: int = 2, ):
        self.http = http_client
        self.scope = http_client.scope
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited: set[str] = set()


    def extract_l(self, html: str, base_url: str,  ) -> list[str]:
        found = []
        if not html:
            return found
        soup = BeautifulSoup(html,"html.parser")
        find_a_tag = soup.find_all("a",href=True)
        for i in find_a_tag:
            href = i["href"].strip()
            if not href:
                continue
            clean_u = self.scope.normalize(base_url, href)
            if self.scope.in_scope(clean_u):
                found.append(clean_u)


        return found

    def crawl(self, start_url: str):
       
        empty = []
        normalize = self.scope.normalize(start_url,"")
        if not self.scope.in_scope(normalize):
            return empty

        queue = deque([(normalize,0)])

        while queue and len(self.visited) < self.max_pages:
          
      
            current_u,popleft = queue.popleft()

            if current_u in self.visited:
                continue

            self.visited.add(current_u)

            page = self.http.get(current_u)
            if page == None:
                continue

            empty.append(page)

                
            if popleft < self.max_depth:
                if "text/html" in page.headers.get("content-type","").lower():

                    extract_l = self.extract_l(page.text, current_u)
                    for link in extract_l:
                        if link not in self.visited:
                            queue.append((link, popleft+1))


        return empty 



