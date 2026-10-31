from patchlens.historydb import Historydatabase
from patchlens.findings import Finding, FindingStatus, Severity, Confidence

def fake_finding(url="https://example.com"):
    finding = Finding(
        check_id = "SEC-HDR-003",
        title = "Missing HSTS header",
        url = url,
        severity = Severity.HIGH,
        confidence = Confidence.CERTAIN,
        description = "Strict-Transport-Security header is missing",
        evidence = "max-age=31536000",
        expected = "max-age=31536000",
        actual = "not set",
        recommendation = "Enable HSTS",
        target_key = "Strict-Transport-Security",)
    return finding

def test_scan_new():
    db = Historydatabase(":memory:")
    target = "https://example.com"
    finding = fake_finding(target)
    vrfy = db.scan_verification(target, [finding])
    assert vrfy[0].status == FindingStatus.NEW


def test_repeated_scans():
    db = Historydatabase(":memory:")
    target = "https://example.com"
    finding_1 = fake_finding(target)
    vrfy_1 = db.scan_verification(target, [finding_1])
    db.scan_save(target, vrfy_1)
    finding_2 = fake_finding(target)
    vrfy_2 = db.scan_verification(target, [finding_2])
    db.scan_save(target, vrfy_2)
    assert vrfy_2[0].status == FindingStatus.OPEN

def test_reaprng_finding():
    db = Historydatabase(":memory:")
    target = "https://example.com"
    finding_1 = fake_finding(target)
    vrfy_1 = db.scan_verification(target, [finding_1])
    db.scan_save(target, vrfy_1)

    vrfy_2 = db.scan_verification(target, [])
    db.scan_save(target, vrfy_2)
    reaprng = fake_finding(target)
    vrfy_3 = db.scan_verification(target, [reaprng])
    assert vrfy_3[0].status == FindingStatus.REOPENED





