# reporting/comparison_report.py
import json, os, datetime
from jinja2 import Environment, FileSystemLoader


class ComparisonReportGenerator:

    OWASP_NAMES = {
        "API1:2023":"BOLA","API2:2023":"Broken Auth","API3:2023":"BOPLA",
        "API4:2023":"Rate Limit","API5:2023":"BFLA","API6:2023":"Biz Logic",
        "API7:2023":"SSRF","API8:2023":"Misconfig","API9:2023":"Inventory",
        "API10:2023":"Unsafe API",
    }

    def __init__(self, output_dir="./reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, target, astra_metrics, zap_metrics, burp_metrics,
                 stats, astra_findings, zap_findings, burp_findings):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # Build per-category detection matrix
        categories = [f"API{i}:2023" for i in range(1, 11)]
        astra_det = set(astra_metrics.get("detected_ids", []))
        zap_det   = set(zap_metrics.get("detected_ids", []))
        burp_det  = set(burp_metrics.get("detected_ids", []))

        matrix = []
        for cat in categories:
            matrix.append({
                "id": cat,
                "name": self.OWASP_NAMES.get(cat, cat),
                "astra": cat in astra_det,
                "zap":   cat in zap_det,
                "burp":  cat in burp_det,
            })

        html = self._build_html(
            target, astra_metrics, zap_metrics, burp_metrics,
            stats, matrix, astra_findings, zap_findings, burp_findings,
            timestamp
        )

        html_path = os.path.join(self.output_dir, f"comparison_report_{timestamp}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        json_data = {
            "type": "comparison_report",
            "target": target,
            "generated": timestamp,
            "tools": {
                "astra": astra_metrics,
                "zap": zap_metrics,
                "burp": burp_metrics,
            },
            "statistical_tests": {
                k: v for k, v in stats.items()
                if isinstance(v, dict) and "p_value" in v
            },
            "detection_matrix": matrix,
        }
        json_path = os.path.join(self.output_dir, f"comparison_report_{timestamp}.json")
        with open(json_path, "w") as f:
            json.dump(json_data, f, indent=2, default=str)

        print(f"  [+] HTML: {html_path}")
        print(f"  [+] JSON: {json_path}")
        return html_path, json_path

    def _build_html(self, target, am, zm, bm, stats, matrix,
                    af, zf, bf, timestamp):
        sev_colors = {"Critical":"#da3633","High":"#e3b341","Medium":"#388bfd","Low":"#3fb950","Info":"#8b949e"}

        matrix_rows = ""
        for row in matrix:
            def cell(val):
                return f'<td style="text-align:center;font-size:1.2em">{"*" if val else "[ ]"}</td>'
            matrix_rows += f"""<tr>
              <td><strong>{row['id']}</strong></td>
              <td>{row['name']}</td>
              {cell(row['astra'])}{cell(row['zap'])}{cell(row['burp'])}
            </tr>"""

        def metrics_card(m, color):
            return f"""<div style="background:#161b22;border-radius:10px;padding:20px;border-top:4px solid {color}">
              <div style="font-size:1.1em;font-weight:700;color:#e6edf3;margin-bottom:12px">{m['tool']}</div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
                <div style="background:#0d1117;padding:10px;border-radius:6px;text-align:center">
                  <div style="font-size:.75em;color:#8b949e;text-transform:uppercase">Precision</div>
                  <div style="font-size:1.8em;font-weight:800;color:{'#3fb950' if m['meets_precision_target'] else '#da3633'}">{m['precision_pct']}%</div>
                </div>
                <div style="background:#0d1117;padding:10px;border-radius:6px;text-align:center">
                  <div style="font-size:.75em;color:#8b949e;text-transform:uppercase">Recall</div>
                  <div style="font-size:1.8em;font-weight:800;color:{'#3fb950' if m['meets_recall_target'] else '#da3633'}">{m['recall_pct']}%</div>
                </div>
                <div style="background:#0d1117;padding:10px;border-radius:6px;text-align:center">
                  <div style="font-size:.75em;color:#8b949e;text-transform:uppercase">F1 Score</div>
                  <div style="font-size:1.8em;font-weight:800;color:{'#3fb950' if m['meets_f1_target'] else '#da3633'}">{m['f1_pct']}%</div>
                </div>
                <div style="background:#0d1117;padding:10px;border-radius:6px;text-align:center">
                  <div style="font-size:.75em;color:#8b949e;text-transform:uppercase">Coverage</div>
                  <div style="font-size:1.8em;font-weight:800;color:#388bfd">{m['owasp_coverage']}</div>
                </div>
              </div>
              <div style="margin-top:12px;font-size:.85em;color:#8b949e">
                TP:{m['tp']} FP:{m['fp']} FN:{m['fn']} | FP Rate:{m['fp_rate_pct']}%
              </div>
            </div>"""

        avz = stats.get("astra_vs_zap", {})
        avb = stats.get("astra_vs_burp", {})
        eci = stats.get("recall_confidence_interval", {})

        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>ASTRA Comparative Evaluation</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;font-size:14px}}
.header{{background:linear-gradient(135deg,#1a1f2e,#0d1117);border-bottom:2px solid #e74c3c;padding:28px 40px}}
h1{{color:#e74c3c;font-size:2em;font-weight:800;letter-spacing:2px}}
.sub{{color:#8b949e;margin-top:4px}}
.container{{max-width:1200px;margin:0 auto;padding:28px 40px}}
.section-title{{font-size:1.3em;color:#e6edf3;margin:28px 0 14px;padding-bottom:8px;border-bottom:1px solid #30363d}}
table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden}}
th{{background:#21262d;color:#8b949e;padding:12px 16px;text-align:left;font-size:.8em;text-transform:uppercase;letter-spacing:.6px}}
td{{padding:11px 16px;border-bottom:1px solid #30363d;font-size:.9em}}
tr:hover td{{background:#1c2128}}
.stat-box{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:12px}}
.sig{{color:#3fb950;font-weight:700}} .not-sig{{color:#da3633;font-weight:700}}
.footer{{text-align:center;padding:24px;color:#8b949e;font-size:.8em;border-top:1px solid #30363d;margin-top:32px}}
</style></head><body>

<div class="header">
  <h1> ASTRA  Comparative Evaluation Report</h1>
  <div class="sub">ASTRA vs OWASP ZAP vs Burp Suite Community · Target: {target} · {timestamp}</div>
</div>

<div class="container">

  <div class="section-title"> Tool Performance Comparison</div>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px">
    {metrics_card(am, '#e74c3c')}
    {metrics_card(zm, '#3498db')}
    {metrics_card(bm, '#e67e22')}
  </div>

  <div class="section-title"> OWASP API Top 10 Detection Matrix</div>
  <table>
    <thead><tr><th>OWASP ID</th><th>Vulnerability</th><th>ASTRA *</th><th>OWASP ZAP</th><th>Burp Suite</th></tr></thead>
    <tbody>{matrix_rows}</tbody>
  </table>

  <div class="section-title"> Statistical Significance Tests</div>
  <div class="stat-box">
    <div style="font-weight:700;color:#e6edf3;margin-bottom:8px">McNemar's Test: ASTRA vs OWASP ZAP</div>
    <div>Chi²: {avz.get('chi2_statistic','N/A')} | p-value: {avz.get('p_value','N/A')} | 
      <span class="{'sig' if avz.get('significant') else 'not-sig'}">
        {'[OK] Statistically Significant' if avz.get('significant') else '[X] Not Significant'}
      </span>
    </div>
    <div style="margin-top:8px;color:#8b949e;font-size:.9em">{avz.get('thesis_statement','')}</div>
  </div>
  <div class="stat-box">
    <div style="font-weight:700;color:#e6edf3;margin-bottom:8px">McNemar's Test: ASTRA vs Burp Suite</div>
    <div>Chi²: {avb.get('chi2_statistic','N/A')} | p-value: {avb.get('p_value','N/A')} |
      <span class="{'sig' if avb.get('significant') else 'not-sig'}">
        {'[OK] Statistically Significant' if avb.get('significant') else '[X] Not Significant'}
      </span>
    </div>
    <div style="margin-top:8px;color:#8b949e;font-size:.9em">{avb.get('thesis_statement','')}</div>
  </div>
  <div class="stat-box">
    <div style="font-weight:700;color:#e6edf3;margin-bottom:8px">ASTRA Recall Confidence Interval (95%)</div>
    <div style="color:#c9d1d9">{eci.get('proportion_pct','N/A')}% [{eci.get('lower_pct','N/A')}%, {eci.get('upper_pct','N/A')}%] at 95% confidence</div>
  </div>

  <div class="section-title"> Summary Metrics Table</div>
  <table>
    <thead><tr><th>Metric</th><th>ASTRA</th><th>OWASP ZAP</th><th>Burp Suite</th><th>ASTRA Target</th></tr></thead>
    <tbody>
      <tr><td>True Positives</td><td>{am['tp']}</td><td>{zm['tp']}</td><td>{bm['tp']}</td><td></td></tr>
      <tr><td>False Positives</td><td>{am['fp']}</td><td>{zm['fp']}</td><td>{bm['fp']}</td><td></td></tr>
      <tr><td>False Negatives</td><td>{am['fn']}</td><td>{zm['fn']}</td><td>{bm['fn']}</td><td></td></tr>
      <tr><td>Precision</td><td style="color:{'#3fb950' if am['meets_precision_target'] else '#da3633'}">{am['precision_pct']}%</td><td>{zm['precision_pct']}%</td><td>{bm['precision_pct']}%</td><td>>=85%</td></tr>
      <tr><td>Recall</td><td style="color:{'#3fb950' if am['meets_recall_target'] else '#da3633'}">{am['recall_pct']}%</td><td>{zm['recall_pct']}%</td><td>{bm['recall_pct']}%</td><td>>=80%</td></tr>
      <tr><td>F1 Score</td><td style="color:{'#3fb950' if am['meets_f1_target'] else '#da3633'}">{am['f1_pct']}%</td><td>{zm['f1_pct']}%</td><td>{bm['f1_pct']}%</td><td>>=82%</td></tr>
      <tr><td>FP Rate</td><td style="color:{'#3fb950' if am['fp_rate_pct']<15 else '#da3633'}">{am['fp_rate_pct']}%</td><td>{zm['fp_rate_pct']}%</td><td>{bm['fp_rate_pct']}%</td><td>&lt;15%</td></tr>
      <tr><td>OWASP Coverage</td><td>{am['owasp_coverage']}</td><td>{zm['owasp_coverage']}</td><td>{bm['owasp_coverage']}</td><td>>=7/10</td></tr>
    </tbody>
  </table>

</div>
<div class="footer">ASTRA Framework · Comparative Evaluation · {timestamp}</div>
</body></html>"""
