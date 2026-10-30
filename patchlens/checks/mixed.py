from bs4 import BeautifulSoup
from patchlens.findings import Finding, Severity, Confidence

class Mixedcontentchecker:
    def check_active(self, url: str, html: str) -> list[Finding]:
        http = (url.lower().startswith("https://"))
        empty = []
        url_check = url.lower().startswith("https://")
        if not url_check or not html:
            return empty
        
        insecure_urls = []
        soup = BeautifulSoup(html, "html.parser")
        scripts_src = soup.find_all("script", src=True)
        for tag0 in scripts_src:

            src = tag0["src"].strip().lower()
            if src.startswith("http://"):
                insecure_urls.append(src)

        scripts_href = soup.find_all("link", href=True)
        for tag1 in scripts_href:
            rel = tag1.get("rel", [])
            rel_str = " ".join(rel).lower() if isinstance(rel, list) else str(rel).lower() 

            if "stylesheet" in rel_str:
                href = tag1["href"].strip().lower()

                if href.startswith("http://"):
                    insecure_urls.append(href)

        scripts_iframe = soup.find_all("iframe", src=True)
        for tag2 in scripts_iframe:

            iframe = tag2["src"].strip().lower()

            if iframe.startswith("http://"):
                insecure_urls.append(iframe)

        if not insecure_urls:
            return empty


        evi = f" insecure active resources in http: {', '.join(insecure_urls)}"
        acul = f"Found {len(insecure_urls)} insecure active resources in https"

        finding = Finding(
            check_id = "SEC-MIX-001",
            title = "Active Mixed Content Detector",
            url = url,
            severity = Severity.HIGH,
            confidence = Confidence.CERTAIN,
            description = "active mixed content which are scripts, stylesheets or iframes are loaded in iframes that allows attackers to alter the DOM, inject malicious code or hijack user sessions" ,
            evidence = evi,
            expected = "All active reponses whaich are scripts, styles, iframes must load over https",
            actual = acul,
            recommendation = " update all scripts, stylesheets, and iframes URLs to use https or relative_path",
            target_key = "mixed-content-active",
            references = ["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],

        )

        return [finding] 

    def check_passive(self, url: str, html: str) -> list[Finding]:
        empty = []
        http = url.strip().lower().startswith("https://") 
        if not http or not html:
            return empty

        insecure_urls = []

        soup = BeautifulSoup(html, "html.parser")
        
        script_img = soup.find_all("img", src = True)
        for tag0 in script_img:
            img = tag0["src"].strip().lower()
            if img.startswith("http://"):
                insecure_urls.append(img)

        script_audio = soup.find_all("audio", src = True)
        for tag1 in script_audio:
            audio = tag1["src"].strip().lower()
            if audio.startswith("http://"):
                insecure_urls.append(audio)

        script_video = soup.find_all("video", src = True)
        for tag2 in script_video:
            video = tag2["src"].strip().lower()
            if video.startswith("http://"):
                insecure_urls.append(video)
        script_source = soup.find_all("source", src = True)
        for tag3 in script_source:
            source = tag3["src"].strip().lower()
            if source.startswith("http://"):
                insecure_urls.append(source)
        
        if not insecure_urls:
            return empty

        evi = f" insecure passive  resources in http : {', '.join(insecure_urls)}"
        acul = f" found {len(insecure_urls)} in plain http"

        finding = Finding(
            check_id = "SEC-MIX-002",
            title = "passive mixed content scanner",
            url = url,
            severity = Severity.LOW,
            confidence = Confidence.CERTAIN,
            description = "Passive mix content which are images, videos , source, audio is in plain http which lets attcker to change or alter those credentials",
            evidence = evi,
            expected = " all media resources must be in https",
            actual = acul,
            recommendation = "update all mix content urls to use https or relative paths",
            target_key = "mixed-content-passive",
            references = ["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
            )

        return [finding]

    def check_all(self, url: str, html: str) -> list[Finding]:
        findings = []
        findings.extend(self.check_active(url, html))
        findings.extend(self.check_passive(url, html))
        
        return findings

    