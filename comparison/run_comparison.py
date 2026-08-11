#!/usr/bin/env python3
# comparison/run_comparison.py
#
# MAIN COMPARISON SCRIPT
# Orchestrates the full comparative evaluation:
#   1. Parse ZAP report -> extract findings
#   2. Parse Burp report -> extract findings
#   3. Load ASTRA results from JSON report
#   4. Calculate Precision/Recall/F1 for all 3 tools
#   5. Run statistical significance tests
#   6. Generate comparison HTML report
#
# How to use:
#   Step 1: Run ASTRA
#     python cli/main.py --target crapi
#     python cli/main.py --target custom_api
#
#   Step 2: Export ZAP report
#     ZAP -> Report -> Generate Report -> XML
#     Save as: reports/zap_report_crapi.xml
#
#   Step 3: Export Burp report
#     Burp -> Target -> Site Map -> Issues -> Report Issues -> XML
#     Save as: reports/burp_report_crapi.xml
#
#   Step 4: Run this script
#     python comparison/run_comparison.py \
#       --astra reports/astra_report_XXXXXXXX.json \
#       --zap   reports/zap_report_crapi.xml \
#       --burp  reports/burp_report_crapi.xml \
#       --target crapi

import sys
import os
import json
import argparse
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from comparison.zap_parser import ZAPParser
from comparison.burp_parser import BurpParser
from core.fp_filter import MetricsCalculator
from analysis.statistical_test import StatisticalTester
from reporting.comparison_report import ComparisonReportGenerator


GROUND_TRUTH = {
    "crapi": {
        "API1:2023": True, "API2:2023": True, "API3:2023": True,
        "API4:2023": True, "API5:2023": True, "API6:2023": True,
        "API7:2023": True, "API8:2023": True, "API9:2023": True,
        "API10:2023": True,
    },
    "custom_api": {
        "API1:2023": True, "API2:2023": True, "API3:2023": True,
        "API4:2023": True, "API5:2023": True, "API6:2023": True,
        "API7:2023": True, "API8:2023": True, "API9:2023": True,
        "API10:2023": True,
    },
    "facebook": {
        "API1:2023": True, "API2:2023": True, "API3:2023": True,
        "API4:2023": True, "API5:2023": True, "API8:2023": True,
    },
    "tmobile": {
        "API1:2023": True, "API2:2023": True, "API3:2023": True,
        "API4:2023": True, "API5:2023": True, "API8:2023": True,
    },
}

BANNER = """

   ASTRA  COMPARATIVE EVALUATION                            
   ASTRA vs OWASP ZAP vs Burp Suite Community                
   Precision / Recall / F1 / Statistical Significance        

"""


def load_astra_results(astra_path: str) -> list:
    """Load findings from ASTRA JSON report."""
    if not astra_path or not os.path.exists(astra_path):
        print(f"  [!] ASTRA report not found: {astra_path}")
        return []
    try:
        with open(astra_path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("findings", [])
    except Exception as e:
        print(f"  [!] Cannot load ASTRA report: {e}")
        return []


def run_comparison(
    astra_path: str,
    zap_path: str,
    burp_path: str,
    target: str,
    output_dir: str = "./reports"
) -> dict:
    print(BANNER)
    print(f"  Target    : {target}")
    print(f"  ASTRA     : {astra_path or 'Not provided'}")
    print(f"  ZAP       : {zap_path or 'Not provided'}")
    print(f"  Burp      : {burp_path or 'Not provided'}")
    print(f"  Output    : {output_dir}\n")

    ground_truth = GROUND_TRUTH.get(target, GROUND_TRUTH["crapi"])

    print("  [*] Loading tool findings...")

    astra_findings = load_astra_results(astra_path) if astra_path else []
    zap_findings = ZAPParser().parse(zap_path) if zap_path else []
    burp_findings = BurpParser().parse(burp_path) if burp_path else []

    print(f"  [+] ASTRA  : {len(astra_findings)} findings")
    print(f"  [+] ZAP    : {len(zap_findings)} findings")
    print(f"  [+] Burp   : {len(burp_findings)} findings")

    print(f"\n{'='*62}")
    print("  CALCULATING METRICS")
    print(f"{'='*62}")

    calc = MetricsCalculator()
    astra_metrics = calc.calculate(astra_findings, ground_truth, "ASTRA")
    zap_metrics   = calc.calculate(zap_findings, ground_truth, "OWASP ZAP")
    burp_metrics  = calc.calculate(burp_findings, ground_truth, "Burp Suite")

    calc.compare_tools(astra_metrics, zap_metrics, burp_metrics)

    print(f"\n{'='*62}")
    print("  STATISTICAL SIGNIFICANCE TESTS")
    print(f"{'='*62}")

    tester = StatisticalTester()
    stats = tester.full_comparison_report(astra_metrics, zap_metrics, burp_metrics)

    print(f"\n{'='*62}")
    print("  GENERATING COMPARISON REPORT")
    print(f"{'='*62}")

    reporter = ComparisonReportGenerator(output_dir)
    html_path, json_path = reporter.generate(
        target=target,
        astra_metrics=astra_metrics,
        zap_metrics=zap_metrics,
        burp_metrics=burp_metrics,
        stats=stats,
        astra_findings=astra_findings,
        zap_findings=zap_findings,
        burp_findings=burp_findings,
    )

    print(f"""

              COMPARISON COMPLETE                            

  Target      : {target:<45}

  Tool        Precision   Recall   F1      Coverage         
  ASTRA       {str(astra_metrics['precision_pct'])+'%':<12}{str(astra_metrics['recall_pct'])+'%':<9}{str(astra_metrics['f1_pct'])+'%':<8}{astra_metrics['owasp_coverage']:<16}
  ZAP         {str(zap_metrics['precision_pct'])+'%':<12}{str(zap_metrics['recall_pct'])+'%':<9}{str(zap_metrics['f1_pct'])+'%':<8}{zap_metrics['owasp_coverage']:<16}
  Burp        {str(burp_metrics['precision_pct'])+'%':<12}{str(burp_metrics['recall_pct'])+'%':<9}{str(burp_metrics['f1_pct'])+'%':<8}{burp_metrics['owasp_coverage']:<16}

  ASTRA meets Precision target (>=85%): {'[OK]' if astra_metrics['meets_precision_target'] else '[X]':<41}
  ASTRA meets Recall target (>=80%):    {'[OK]' if astra_metrics['meets_recall_target'] else '[X]':<41}
  ASTRA meets F1 target (>=82%):        {'[OK]' if astra_metrics['meets_f1_target'] else '[X]':<41}

  HTML Report: {str(html_path)[-46:]:<46}
  JSON Report: {str(json_path)[-46:]:<46}

""")

    return {
        "astra": astra_metrics,
        "zap": zap_metrics,
        "burp": burp_metrics,
        "stats": stats,
    }


def main():
    parser = argparse.ArgumentParser(
        description="ASTRA Comparative Evaluation  ASTRA vs ZAP vs Burp"
    )
    parser.add_argument("--astra", help="Path to ASTRA JSON report")
    parser.add_argument("--zap",   help="Path to ZAP XML/JSON report")
    parser.add_argument("--burp",  help="Path to Burp XML report")
    parser.add_argument(
        "--target", default="crapi",
        choices=["crapi", "custom_api", "facebook", "tmobile"],
        help="Target that was scanned"
    )
    parser.add_argument("--output", default="./reports", help="Output directory")
    args = parser.parse_args()

    if not any([args.astra, args.zap, args.burp]):
        print("""
  Usage example:

  python comparison/run_comparison.py \\
    --astra  reports/astra_report_20260514.json \\
    --zap    reports/zap_crapi_report.xml \\
    --burp   reports/burp_crapi_report.xml \\
    --target crapi \\
    --output ./reports

  You need at least one report file to compare.
        """)
        return

    run_comparison(
        astra_path=args.astra,
        zap_path=args.zap,
        burp_path=args.burp,
        target=args.target,
        output_dir=args.output,
    )


if __name__ == "__main__":
    main()
