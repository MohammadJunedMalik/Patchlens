import sqlite3
import json
from datetime import datetime, timezone 
from patchlens.findings import Finding, FindingStatus
import uuid

class Historydatabase:
    def __init__(self, db_path: str = "patchlens.db"):
        self.conn = sqlite3.connect(db_path)
        self.create_tables() 

    def create_tables(self):
        cr = self.conn.cursor()

        cr.execute("""
        CREATE TABLE IF NOT EXISTS scans(
        scan_id TEXT PRIMARY KEY ,
        target_url TEXT,
        timestamp TEXT,
        total_findings INTEGER) """)

        cr.execute(""" CREATE TABLE IF NOT EXISTS findings(
        fingerprint TEXT,
        scan_id TEXT,
        check_id TEXT,
        title TEXT,
        url TEXT,
        severity TEXT,
        status TEXT,
        evidence TEXT,
        recommendation TEXT,
        PRIMARY KEY (scan_id, fingerprint) )""")

        self.conn.commit()

    def scan_save(self, target_url: str, findings: list[Finding], scan_id: str = "") -> None:

        if not scan_id:
            scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        
        cr = self.conn.cursor()
        timestamp = findings[0].timestamp if findings else datetime.now(timezone.utc).isoformat()
        cr.execute("INSERT INTO scans VALUES (?,?,?,?)", (scan_id, target_url, timestamp, len(findings)))
        
        for f in findings:
            cr.execute("INSERT INTO findings ( fingerprint, scan_id, check_id, title, url, severity, status, evidence, recommendation) VALUES (?,?,?,?,?,?,?,?,?)", (
                f.fingerprint,
                scan_id,
                f.check_id,
                f.title,
                f.url,
                f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                f.status.value if hasattr(f.status, "value") else str(f.status),
                f.evidence,
                f.recommendation))
        
        
        self.conn.commit()
        return scan_id

    def recent_scan(self, target_url: str):
        cr = self.conn.cursor()

        cr.execute("""SELECT scan_id, target_url, timestamp, total_findings FROM scans WHERE target_url = ? ORDER BY timestamp DESC LIMIT 1""", (target_url,))
        row = cr.fetchone()

        if not row:
            return None
        return{ "scan_id" : row[0],
               "target_url" : row[1],
               "timestamp" : row[2],
               "total_findings" : row[3],}

    
    def take_scan_findings(self, scan_id: str):
        cr = self.conn.cursor()
        cr.execute("""SELECT fingerprint, check_id, title, url, severity, status, evidence, recommendation FROM findings WHERE scan_id = ? """, (scan_id,))
        rows = cr.fetchall()
        finding = {}

        for s in rows:
            finding[s[0]] = {
                "fingerprint" : s[0], 
                "check_id" :s[1] , 
                "title" : s[2], 
                "url" : s[3], 
                "severity" : s[4], 
                "status" : s[5], 
                "evidence" : s[6], 
                "recommendation" : s[7] }

        return finding

   

    def scan_verification(self, target_url: str, current_findings: list[Finding]) -> list[Finding] :
        recent = self.recent_scan(target_url)
        if not recent:
            for f in current_findings:
                f.status = FindingStatus.NEW
            return current_findings

        previous_scan = self.take_scan_findings(recent["scan_id"])
        for f in current_findings:
                if f.fingerprint in previous_scan:
                    if previous_scan[f.fingerprint]["status"] == FindingStatus.RESOLVED:
                        f.status = FindingStatus.REOPENED
                    else:
                        f.status = FindingStatus.OPEN
                else:
                    f.status = FindingStatus.NEW

        set_findings =  {f.fingerprint for f in current_findings}
        for pre in previous_scan.values():
            if pre["fingerprint"] not in set_findings:
                if pre["status"] in ("OPEN", "NEW"):
                    
                    finding = Finding(
                    fingerprint = pre["fingerprint"],
                    check_id = pre["check_id"],
                    title = pre["title"],
                    url = pre["url"],
                    severity = pre["severity"],
                    confidence = "CERTAIN",
                    description = "Resolved finding",
                    evidence = pre["evidence"],
                    expected = "",
                    actual = "",
                    recommendation = pre["recommendation"],
                    status=FindingStatus.RESOLVED,)

                    current_findings.append(finding) 
        return current_findings









