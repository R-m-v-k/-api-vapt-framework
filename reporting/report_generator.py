# report_generator.py  ASTRA Reporting Module

import json
import os
import datetime
from typing import List, Dict
from jinja2 import Environment, FileSystemLoader


class ReportGenerator:

    OWASP_MAP = [
        {"id": "API1:2023", "name": "BOLA"},
        {"id": "API2:2023", "name": "Broken Auth"},
        {"id": "API3:2023", "name": "BOPLA"},
        {"id": "API4:2023", "name": "Rate Limiting"},
        {"id": "API5:2023", "name": "BFLA"},
        {"id": "API6:2023", "name": "Business Logic"},
        {"id": "API7:2023", "name": "SSRF"},
        {"id": "API8:2023", "name": "Misconfiguration"},
        {"id": "API9:2023", "name": "Inventory"},
        {"id": "API10:2023", "name": "Unsafe Consumption"},
    ]

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, all_findings: List[Dict], target_url: str,
                 scan_start: datetime.datetime, scan_end: datetime.datetime):

        duration = str(scan_end - scan_start).split(".")[0]
        scan_date = scan_end.strftime("%Y-%m-%d %H:%M:%S")
        timestamp = scan_end.strftime("%Y%m%d_%H%M%S")

        # Flatten all findings
        findings = []
        for module_result in all_findings:
            for f in module_result.get("findings", []):
                findings.append(f)

        # Summary
        summary = {
            "critical": sum(1 for f in findings if f["severity"] == "Critical"),
            "high": sum(1 for f in findings if f["severity"] == "High"),
            "medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "low": sum(1 for f in findings if f["severity"] == "Low"),
            "total": len(findings),
        }

        # Coverage
        detected_ids = set(f["owasp_id"] for f in findings)
        coverage = [
            {**item, "detected": item["id"] in detected_ids}
            for item in self.OWASP_MAP
        ]

        # Save JSON report
        json_report = {
            "framework": "ASTRA v1.0",
            "target": target_url,
            "scan_date": scan_date,
            "duration": duration,
            "summary": summary,
            "coverage": {
                "detected": len(detected_ids),
                "total": 10,
                "percentage": round(len(detected_ids) / 10 * 100, 1),
            },
            "findings": findings,
        }

        json_path = os.path.join(self.output_dir, f"astra_report_{timestamp}.json")
        with open(json_path, "w") as f:
            json.dump(json_report, f, indent=2, default=str)

        # Save HTML report
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        env = Environment(loader=FileSystemLoader(template_dir))

        try:
            env.filters['tojson'] = lambda v, **kw: json.dumps(v, indent=kw.get('indent', None), default=str)
            template = env.get_template("report.html")
            html_content = template.render(
                target_url=target_url,
                scan_date=scan_date,
                duration=duration,
                summary=summary,
                coverage=coverage,
                findings=findings,
            )
            html_path = os.path.join(self.output_dir, f"astra_report_{timestamp}.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
        except Exception as e:
            html_path = None
            print(f"  [!] HTML report error: {e}")

        return json_path, html_path, summary, coverage
