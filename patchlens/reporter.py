import json
from patchlens.findings import Finding, Severity

class Reporter:
    def __init__(self, findings: list[Finding], target_url: str= ""):
        self.findings = findings
        self.target_url = target_url

    def summary_counts(self) -> dict[str, int]:
        c_h = c_m = c_l = c_I = c_CR = 0
        for i in self.findings:
            if i.severity == "HIGH":
                c_h += 1
            elif i.severity == "MEDIUM":
                c_m += 1
            elif i.severity == "LOW":
                c_l += 1
            elif i.severity == "INFO":
                c_I += 1
            elif i.severity == "CRITICAL":
                c_CR += 1

        return { 
            "LOW" : c_l, 
            "MEDIUM" : c_m,
            "HIGH" : c_h, 
            "INFO" : c_I , 
            "CRITICAL" : c_CR, }

    def in_json(self, filepath: str= "") -> str:
        dic = {
            "target_url" : self.target_url,
            "status_summary" : self.count_status(),
            "summary": self.summary_counts(),
            "total_findings": len(self.findings),
            "findings" :  [f.to_dict() for f in self.findings],
        }
        str_json = json.dumps(dic, indent=2)
        if filepath:
            with open(filepath, "w") as f:
                f.write(str_json)

        return str_json

    def count_status(self) -> dict[str, int]:
        c_n = c_o = c_res = c_reop = 0
        for f in self.findings:
            if str(f.status) in "NEW":
                c_n += 1 
            elif str(f.status) in "OPEN":
                c_o += 1 
            elif str(f.status) in "RESOLVED":
                c_res += 1
            elif str(f.status) in "REOPENED":
                c_reop += 1  
        return {"NEW" : c_n,
                "OPEN" : c_o,
                "RESOLVED" : c_res,
                "REOPENED" : c_reop,}


    def summary(self) -> None:
        count = self.summary_counts()
        print('='*100)
        print("\t PATCHLENS REPORT \t")
        print("="*100)
        print(f"Target URL : {self.target_url}")
        print(f"TOTAL Findings : {len(self.findings)}")
        print('='*100)
        print(f"CRITICAL: {count["CRITICAL"]}")
        print(f"HIGH: {count["HIGH"]}")
        print(f"MEDIUM: {count["MEDIUM"]}")
        print(f"LOW: {count["LOW"]}")
        print(f"INFO: {count["INFO"]}")
        print('='*100)
        print(f"Status_summary : {self.count_status()}")
        print('='*100)



