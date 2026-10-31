from patchlens.checks.headers import Headerchecker 
from patchlens.checks.cookies import Cookiechecker
from patchlens.checks.mixed import Mixedcontentchecker  

def test_sec_headr():
    findings = Headerchecker().check_all("https://example.com", {})

    cks_id = [f.check_id for f in findings]
    assert "SEC-HDR-001" in cks_id 
    assert "SEC-HDR-002" in cks_id 
    assert "SEC-HDR-003" in cks_id 
    assert "SEC-HDR-004" in cks_id 

def test_proprly_headr():
    cks = Headerchecker()
    secr_headr = { "X-Content-Type-Options" : "nosniff",
                  "X-Frame-Options" : "DENY",
                  "Strict-Transport-Security" : "max-age=31536000; includeSubDomains",
                  "Content-Security-Policy" : "default-src 'self'",
                  "Referrer-Policy" : "strict-origin-when-cross-origin", }

    findings = cks.check_all("https://example.com", secr_headr)
    assert len(findings) == 0


def test_cookie_insecr():
    cks = Cookiechecker()
    headr = {"Set-Cookie" : "session_id=secret123"}
    findings = cks.check_all("https://example.com", headr)
    assert len(findings) == 3
    cks_id = [f.check_id for f in findings]
    assert "SEC-CK-001" in cks_id
    assert "SEC-CK-002" in cks_id
    assert "SEC-CK-003" in cks_id



def test_cookie_hrdnd():
    cks = Cookiechecker()
    headr = {"Set-Cookie" : "session_id=secret123; Secure; Httponly; Samesite=Strict"}
    findings = cks.check_all("https://example.com", headr)
    assert len(findings) == 0


def test_mix_cntnt():
    cks = Mixedcontentchecker()
    html = """
<html>
<head>
<script src="http://insecure.example.com/app.js"></script>
</head>
<html> """
    findings = cks.check_active("https://example.com", html)
    assert len(findings) == 1
    assert findings[0].check_id == "SEC-MIX-001"


def test_mix_cntnt_ignr():
    cks = Mixedcontentchecker()
    html = "<script src='http://insecure.example.com/app.js'></script>"
    findings = cks.check_active("http://example.com", html)
    assert len(findings) == 0






