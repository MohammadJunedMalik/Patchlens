# I have imported 3 classes from the findings.py file
from patchlens.findings import Finding, Severity, Confidence
class Headerchecker:
# this one checks header whether it is sniff or nosniff
    def check_content(self, url: str, headers):
        empty = []
        raw = headers.get("X-Content-Type-Options","")
        content = raw.strip().lower()
        acul = ""
        evi = ""
        if content == "nosniff":
            return empty

        if  raw:
            evi = f"X-Content-Type-Options header has invalid value : '{raw}'"
            acul = raw
        else:
            evi = "Header not present"
            acul = "not set"

       
        finding = Finding(check_id = "SEC-HDR-001",
            title = "missing or ineffective 'X-Content-type-Options Header'",
            url = url,
            severity = Severity.LOW,
            confidence = Confidence.CERTAIN,
            description = "the X-Content-Type-Options header instructs the browser not to MIME-sniff the response body away from the declared Content-Type, mitigating MIME confusion attacks",
            evidence = evi,
            expected = "X-Content-Type-Options: nosniff",
            actual = acul,
            recommendation = "Configure your web server or application frame to send 'X-Content-Type-Options: nosniff' on all http responses",
            target_key = "X-Content-Type-Options",
            references = ["https://owasp.org/www-project-secure-headers/#x-content-type-options"]
        )

        return [finding]

    # this checks whether a user is tricket to click hidden or fake button this type of attack also known as clickjacking or User interface(UI) attack
    def check_frame_options(self, url: str, headers) -> list[Finding]:
        take = headers.get("X-Frame-Options","")
        raw = take.strip().upper()
        evi =""
        acul = ""
        empty = []

        if raw in ("DENY","SAMEORIGIN"):
            return empty
        if raw:
            evi = f"X-Frame-Options header has invalid value : '{raw}'"
            acul = raw

        else:
            evi = "Header is not present"
            acul = "not set"

        finding = Finding(
            check_id = "SEC-HDR-002",
            title = "missing or weak protection 'X-Frame-Options'",
            url = url,
            severity = Severity.MEDIUM,
            confidence = Confidence.CERTAIN,
            description = "The X-Frame-Options HTTP response header indicates that whether a browser should be allowed to render a page in object , frame, iframe, embed to prevent attackts",
            evidence = evi,
            expected = "X-Frame-Options: DENY or SAMEORIGIN",
            actual = acul,
            recommendation = "Send 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' or use content sevurity policy with 'frame-ancestors' ",
            target_key = "X-Frame-Options",
            references = ["https://owasp.org/www-project-secure-headers/#x-frame-options"]
            )
        return [finding]
    
    # it stops the http request because an attacker can slow down or downgrade the connection and it automatically convert http to https .
    def check_hsts(self, url: str, headers) -> list[Finding]:
        empty = []

        if not url.startswith("https://"):
            return empty
        
        take = headers.get("Strict-Transport-Security","")
        raw = take.strip().lower()

        evi = ""
        acul = ""

        if raw:
            if "max-age" in raw:
                return empty
            else:
                evi = f"HSTS header present but missing 'max_age': '{raw}'"
                acul = raw

        else:
            evi = f"Strict-Transport-Security header not present in https response"
            acul = "not set"

        finding = Finding( 
            check_id = "SEC-HDR-003",
            title = "Missing or misconfigured http strict transport security(HSTS)",
            url = url,
            severity = Severity.MEDIUM,
            confidence = Confidence.CERTAIN,
            description = "HSTS  ensures the browser only communicates over https with the server",
            evidence = evi,
            expected = "Strict-Transport-Security",
            actual = acul,
            recommendation = "it Enable hsts by adding 'Strict-Transport-Security: max-age=31536000; also includes subdomain to all https responses",
            target_key = "Strict-Transport-Security",
            references = ["https://owasp.org/www-project-secure-headers/#http-strict-transport-security"],
            )

        return [finding]

    # if  an attacker finds an opening , they can inject some dangerous or malicious files , it implements cross-site scripting  (CSP) and tells the bowser only execute , run or load from the given and approved sources"
    def check_csp(self, url: str, headers):
        take = headers.get("Content-Security-Policy","")
        raw = take.strip().lower()
        empty = []
        evi = ""
        acul = ""
        if raw :
            if "default-src" in raw or "script-src" in raw:
                return empty
            else:
                evi = f"CSP header is present but lacks 'default-src' or 'script-src' fallback: '{raw}'"
                acul = raw
        else:
            evi = "Content-Security-Policy header is not present"
            acul = "not set"

        finding = Finding(
            check_id = "SEC-HDR-004",
            title = "missing or incomplete CSP(content security policy)",
            url = url,
            severity = Severity.MEDIUM,
            confidence = Confidence.CERTAIN,
            description = "CSP restricts the resources (scripts, images, stylesheets) to prevent the data injection and xss scripting attack",
            evidence = evi,
            expected = "Content-Security-Policy: default-src 'self'",
            actual = acul,
            recommendation = "Implement CSP starting with 'default-src' 'self' and only allow necessary and approved sited",
                    target_key = "Content-Security-Policy",
                    references = ["https://owasp.org/www-project-secure-headers/#content-security-policy"],
            )

        return [finding]
    
    # it checks referrer policy in the referrer header and prevents 
    def check_referrer_policy(self, url: str, headers) -> list[Finding]:
        take = headers.get("Referrer-Policy","")
        raw =  take.strip().lower()
        safe_policy = {"no-referrer", "strict-origin-when-cross-origin", "same-origin", "strict-origin", "origin-when-cross-origin", "no-referrer-when-downgrade", "origin"}
        empty = []
        evi = ""
        acul = ""
        
        if raw in safe_policy:
            return empty

        if raw :
            evi = f"Referrer-Policy header has unsafe or invalid value: '{raw}'"
            acul = raw

        else:
            evi = "Referrer_Policy is not present"
            acul = "not set"

        finding = Finding(
            check_id = "SEC-HDR-005",
            title = "missing or has insecure referrer policy header",
            url = url , 
            severity = Severity.LOW ,
            confidence = Confidence.CERTAIN , 
            description = "Referrer-Policy means which referrer info. should be sent with requests which prevents data leaks",
            evidence = evi,
            expected = "Referrer-Policy: no-referrer or strict-origin-when-cross-origin",
            actual = acul,
            recommendation = "Set 'Referrer-Policy: strict-origin-when-cross-origin' to prevent data leaks",
            target_key = "Referrer-Policy",
            references = ["https://owasp.org/www-project-secure-headers/#referrer-policy"]
            )

        return [finding]
    
    # it stopps attackers to step in servers from the given software and their versions and it let the servers to minimize these headers 
    def check_server(self, url: str, headers) -> list[Finding]:
        find = []
        
        evi = ""
        acul = ""
        take = headers.get("X-Powered-By","")
        raw = take.strip().lower()

        if raw:
            evi = f"X-Powered-By header is exposed : '{raw}'"
            acul = raw
        

            finding = Finding(
                check_id = "SEC-HDR-006",
                title = "Technology Disclosure via X-Powered-By header",
                url = url,
                severity = Severity.LOW,
                confidence = Confidence.CERTAIN,
                description = "X-Powered-By header exposes underlying server-side and it's technologies",
                evidence = evi,
                expected = "Header should not be present",
                actual = acul,
                recommendation = " Disable X-Powered-By header in your application or server configure",
                target_key = "X-Powered-By",
                references = ["https://owasp.org/www-project-secure-headers/#x-powered-by"]
            )
            find.append(finding)
        else:
            evi = "X-Powered-By header is not present"
            acul = "not set"

        server = headers.get("Server","")
        raw_server = server.strip().lower()
        evi_server = ""
        acul_server = ""
        if raw_server :
           
                if any(char.isdigit() for char in raw_server):
                    finding_server = Finding(
                        check_id = "SEC-HDR-007",
                        title = "Detailed server disclosure in header",
                        url = url,
                        severity = Severity.INFO,
                        confidence = Confidence.CERTAIN,
                        description = "Server responses header discloses the web server software and it's specific version number",
                        evidence = f"Server header exposed software version is : '{raw_server}'",
                        expected = f"server header should be showed without version numbers",
                        actual = raw_server,
                        recommendation = "Configure web server to suppress detailed verion numbers or tokens",
                        target_key = "Server",
                        references = ["https://owasp.org/www-project-secure-headers/#server"]
                        )
                    find.append(finding_server)

        return find

    def check_all(self, url: str, headers) -> list[Finding]:
        findings = []
        findings.extend(self.check_content(url, headers))
        findings.extend(self.check_frame_options(url, headers))
        findings.extend(self.check_hsts(url, headers))
        findings.extend(self.check_csp(url, headers))
        findings.extend(self.check_referrer_policy(url, headers))
        findings.extend(self.check_server(url, headers))

        return findings

    