import ssl 
import socket
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
from patchlens.findings import Finding, Severity, Confidence

class Tlschecker:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def take_hostname_port(self, url: str) -> tuple[str, int]:
        parse = urlparse(url if "://" in url else f"https://{url}")
        hostname = parse.hostname or url
        port = parse.port or (443 if parse.scheme=="https" else 80)

        return hostname, port

    def check_certificate(self, url: str) -> list[Finding]:
        findings = []

        hostname, port = self.take_hostname_port(url)
        tls_port = port if port != 80 else 443
        context = ssl.create_default_context()

        try : 
            with socket.create_connection((hostname, tls_port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as context_socket:
                    cert = context_socket.getpeercert()

            no_str = cert.get("notAfter")

            if no_str:
                expiry_date = datetime.strptime(no_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expiry_date - now).days

                if days_left < 0:
                    finding = Finding(
                        check_id = "SEC-TLS-001",
                        title = "Expired SSl/TLS Certificate",
                        url = url,
                        severity = Severity.HIGH,
                        confidence = Confidence.CERTAIN,
                        description = " ssl/tls certificate has been expired which is raising web security warning and broken trust",
                        evidence = f"the certificate expired on {no_str} ({abs(days_left)})",
                        expected = f"certificate not be expired",
                        actual = f"it expired on {no_str}",
                        recommendation = " renew and install tls/ssh",
                        target_key = "tls-certificate-validity",
                        references = ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web-Application_Security_Testing/09-Testingg_for_Weak_Cyptography/03-Testing_for_Weak_Transport_Layer_Security"],
                    )
                    findings.append(finding)
                elif days_left<=14:
                    finding = Finding(
                            check_id = "SEC-TLS-002",
                            title = "SSl/TLS Certificate will going to expire soon",
                            url = url,
                            severity = Severity.LOW,
                            confidence = Confidence.CERTAIN,
                            description = f" ssl/tls is going to expire in {days_left}",
                            evidence = f"the certificate expired on {no_str} and the days left ({abs(days_left)})",
                            expected = f"renew the certificate before expiring date",
                            actual = f"days left : {days_left}",
                            recommendation = " renew the tls/ssh before the expiry date" ,
                            target_key = "tls-certificate-expiry",
                            references = ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                                        )
                    findings.append(finding)

        except ssl.SSLCertVerificationError as e:
            finding = Finding(
                            check_id = "SEC-TLS-001",
                            title = "invalid SSl/TLS Certificate",
                            url = url,
                            severity = Severity.HIGH,
                            confidence = Confidence.CERTAIN,
                            description = " ssl/tls certificate has failed verification",
                            evidence = f"ssl/tls verification error {e.verify_message if hasattr(e,'verify_message') else e}",
                            expected = f"a trustworthy certificate is to be issued by a recognized authority matching the hostname",
                            actual = str(e),
                            recommendation = " install verified tls/ssh certificate from an authorized authority",
                            target_key = "tls-certificate-validity",
                            references = ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                            )
            findings.append(finding)

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            finding = Finding(
                    check_id = "SEC-TLS-001",
                    title = "failed connection of SSl/TLS Certificate",
                    url = url,
                    severity = Severity.HIGH,
                    confidence = Confidence.CERTAIN,
                    description = "unable to connect tls connection on port 443",
                    evidence = f"connection failure: {str(e)}",
                    expected = f"https o port 443 should accept tls connection",
                    actual = "connection failed or timed out",
                    recommendation = " enable and configure https listening on 443 ",
                    target_key = "tls-certificate-validity",
                    references = ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                            )
            findings.append(finding)

        return findings


    def check_http_redirect(self, url: str) -> list[Finding]:
            findings = []
            hostname, _ = self.take_hostname_port(url)
            http_url = f"http://{hostname}/"

            try:
                get = requests.get(http_url, allow_redirects=False, timeout=self.timeout)


                if get.status_code == 200:
                    finding =  Finding(
                                check_id = "SEC-TLS-003",                       
                                title = "http available but not redirecting in https",
                                url = http_url,
                                severity = Severity.MEDIUM,
                                confidence = Confidence.CERTAIN,
                                description = "it serves content in plain http not redirecting in https",
                                evidence = f" http responded with status {get.status_code} and without redirecting to https",
                                expected = "http requests should return 301 redirect to https",
                                actual = f"http status code : {get.status_code}",
                                recommendation = "enforce http to redirect in https",
                                target_key = "http-to-https-redirect",
                                references = ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"]
                        
                                )
                    findings.append(finding)

                elif get.status_code in(301,302,307,308):
                    location = get.headers.get("Location", "")
                    if not location.lower().startswith("https://"):
                        finding = Finding(
                            check_id = "SEC-TLS-003",
                            title = "http does not in https",
                            url = http_url,
                            severity = Severity.MEDIUM,
                            confidence = Confidence.CERTAIN,
                            description = "http version of the site redirects, but the target destination is not secure https",
                            evidence = f" http responded with status {get.status_code} and redirecting to {location}",
                            expected = "http requests should redirected in https url not in http",
                            actual = f"redirected location is : {location}",
                            recommendation = "Configure your web server to redirect all http to https",
                            target_key = "http-to-https-redirect",
                            references = ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                        )
                        findings.append(finding)
                

            except requests.RequestException as e:
                pass

            return findings


    def check_all(self, url: str) -> list[Finding]:
            findings = []
            findings.extend(self.check_certificate(url))
            findings.extend(self.check_http_redirect(url))

            return findings


    