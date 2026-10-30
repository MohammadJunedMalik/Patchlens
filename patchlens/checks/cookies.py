from patchlens.findings import Finding, Severity, Confidence

class Cookiechecker:
    def check_secure_flag(self, url: str, cookie_name : str, raw: str) -> list[Finding]:
        split_raw = [part.strip().lower() for part in raw.split(';')]
        empty = []
        
        
        if "secure" in split_raw:
            return empty
        else:
            evi = f"Cookie '{cookie_name}' is missing the 'Secure' in : '{raw}' "
            acul = "Secure attribute not set"
        finding = Finding(
            check_id = "SEC-CK-001",
            title = f"Cookie missing 'Secure' : '{cookie_name}'",
            url = url,
            severity = Severity.MEDIUM,
            confidence = Confidence.CERTAIN,
            description = "'Secure' attributes instructs browsers to only transmit cookie in https (encrypted) connections , prevents interception on insecure networks " ,
            evidence = evi,
            expected = f"Set cookie {cookie_name} = secure",
            actual = acul,
            recommendation = f" add the 'Secure' to the cookie-header for {cookie_name}",
            target_key = cookie_name,
            references = ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            )

        return [finding]

    def check_httponly_flag(self, url: str, cookie_name: str, raw: str) -> list[Finding]:
        split_raw = [part.strip().lower() for part in raw.split(';')]
        empty = []
        if 'httponly' in split_raw:
            return empty

        evi = f"cookie 'Httponly' {cookie_name} is missing in {raw}"
        acul = f"httponly is not set "

        finding = Finding(
            check_id = 'SEC-CK-002',
            title = f"Cookie is missing 'Httponly' : '{cookie_name}'",
            url = url,
            severity = Severity.MEDIUM,
            confidence = Confidence.CERTAIN,
            description = " httponly is missing from the url",
            evidence = evi,
            expected = f"set cookie : {cookie_name} = Httponly",
            actual = acul,
            recommendation = f" add the 'Httponly' in the cookie : {cookie_name}",
            target_key = cookie_name,
            references = ["https://owasp.org/www-community/Httponly"],
            )

        return [finding]

    def check_samesite_flag(self, url: str, cookie_name: str, raw: str):
        split_raw = [part.strip().lower() for part in raw.split(';')]
        empty = []
        if any(parts.startswith('samesite') for parts in split_raw):
            return empty

        evi = f"Cookie 'samesite' {cookie_name} is missing in {raw}"
        acul = f" samesite is not set"

        finding = Finding(
            check_id = "SEC-CK-003",
            title = f"samesite cookie is missing :{cookie_name}",
            url = url,
            severity = Severity.MEDIUM,
            confidence = Confidence.CERTAIN,
            description = "samesite cookie prevent the CSRF( Cross-site request Forgery)",
            evidence = evi,
            expected = f" set cookie : {cookie_name} = samesite",
            actual = acul,
            recommendation = f" add the samesite in the cookie header : '{cookie_name}'",
            target_key = cookie_name,
            references = ["https://owasp.org/www-community/Httponly"]
            )

        return [finding]


    def check_all(self, url: str, headers: dict) -> list[Finding]:
        findings = []
        raw =  headers.get("Set-Cookie") or headers.get("set-cookie")
        if not raw:
            return findings
        part = raw.split(';')[0].strip()
        cookie_name = part.split("=")[0].strip() if "=" in part else part

        findings.extend(self.check_secure_flag(url, cookie_name, raw))
        findings.extend(self.check_httponly_flag(url, cookie_name, raw))
        findings.extend(self.check_samesite_flag(url, cookie_name, raw))


        return findings

    

    