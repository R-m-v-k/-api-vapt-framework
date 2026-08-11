# analysis/statistical_test.py
#
# Statistical Significance Testing
# Uses McNemar's test and Chi-square to prove ASTRA's
# improvement over ZAP and Burp is statistically significant
#
# Academic justification:
#   Without statistical testing, a board can argue your
#   results are due to chance. McNemar's test is the
#   standard in security tool comparison papers.
#
# Where it is used:
#   Called after comparison/run_comparison.py
#   Results go into Chapter 5 (Results) of thesis

import math
from typing import Dict, List, Tuple


class StatisticalTester:
    """
    Performs statistical significance tests on tool comparison results.
    Uses McNemar's test (paired binary outcomes) which is standard
    for comparing two classifiers on the same dataset.
    """

    ALPHA = 0.05  # 95% confidence level

    def mcnemar_test(
        self,
        tool_a_detections: List[bool],
        tool_b_detections: List[bool],
        tool_a_name: str = "ASTRA",
        tool_b_name: str = "ZAP"
    ) -> Dict:
        """
        McNemar's test for paired binary outcomes.
        Tests if the difference in detection rates between
        two tools is statistically significant.

        Args:
            tool_a_detections: List of True/False for each vulnerability
            tool_b_detections: List of True/False for each vulnerability

        Returns:
            Statistical test result with p-value and interpretation
        """
        if len(tool_a_detections) != len(tool_b_detections):
            return {"error": "Lists must be same length"}

        # Build contingency table
        # b = A detects, B misses
        # c = B detects, A misses
        b = sum(1 for a, bv in zip(tool_a_detections, tool_b_detections) if a and not bv)
        c = sum(1 for a, bv in zip(tool_a_detections, tool_b_detections) if not a and bv)
        a_both = sum(1 for av, bv in zip(tool_a_detections, tool_b_detections) if av and bv)
        d_neither = sum(1 for av, bv in zip(tool_a_detections, tool_b_detections) if not av and not bv)

        # McNemar's statistic with continuity correction
        if (b + c) == 0:
            chi2 = 0
            p_value = 1.0
        else:
            chi2 = (abs(b - c) - 1) ** 2 / (b + c)
            p_value = self._chi2_p_value(chi2, df=1)

        significant = p_value < self.ALPHA

        result = {
            "test": "McNemar's Test (with continuity correction)",
            "tool_a": tool_a_name,
            "tool_b": tool_b_name,
            "contingency_table": {
                "both_detect": a_both,
                f"only_{tool_a_name}_detects": b,
                f"only_{tool_b_name}_detects": c,
                "neither_detects": d_neither,
            },
            "chi2_statistic": round(chi2, 4),
            "p_value": round(p_value, 4),
            "alpha": self.ALPHA,
            "significant": significant,
            "interpretation": (
                f"The difference between {tool_a_name} and {tool_b_name} "
                f"is {'statistically significant' if significant else 'NOT statistically significant'} "
                f"at the α={self.ALPHA} level (p={'<0.05' if significant else '>0.05'})."
            ),
            "thesis_statement": self._generate_thesis_statement(
                tool_a_name, tool_b_name, significant, b, c, p_value
            ),
        }

        self._print_result(result)
        return result

    def effect_size(
        self,
        tool_a_recall: float,
        tool_b_recall: float,
        n_tests: int = 10
    ) -> Dict:
        """
        Calculate Cohen's h effect size for two proportions.
        Quantifies practical significance of improvement.
        """
        p1 = tool_a_recall / 100
        p2 = tool_b_recall / 100

        phi1 = 2 * math.asin(math.sqrt(p1))
        phi2 = 2 * math.asin(math.sqrt(p2))
        h = abs(phi1 - phi2)

        # Interpret effect size
        if h < 0.2:
            interpretation = "Small effect"
        elif h < 0.5:
            interpretation = "Medium effect"
        elif h < 0.8:
            interpretation = "Large effect"
        else:
            interpretation = "Very large effect"

        return {
            "cohens_h": round(h, 4),
            "interpretation": interpretation,
            "tool_a_recall": tool_a_recall,
            "tool_b_recall": tool_b_recall,
            "absolute_difference": round(abs(tool_a_recall - tool_b_recall), 1),
        }

    def confidence_interval(
        self,
        successes: int,
        total: int,
        confidence: float = 0.95
    ) -> Dict:
        """
        Wilson confidence interval for a proportion.
        Used to report confidence intervals around precision/recall.
        """
        if total == 0:
            return {"lower": 0, "upper": 0, "proportion": 0}

        p = successes / total
        z = 1.96  # 95% CI
        denominator = 1 + z**2 / total
        centre = (p + z**2 / (2 * total)) / denominator
        margin = z * math.sqrt(p * (1-p) / total + z**2 / (4 * total**2)) / denominator

        return {
            "proportion_pct": round(p * 100, 1),
            "lower_pct": round(max(0, centre - margin) * 100, 1),
            "upper_pct": round(min(1, centre + margin) * 100, 1),
            "confidence_level": f"{int(confidence*100)}%",
        }

    def full_comparison_report(
        self,
        astra_metrics: Dict,
        zap_metrics: Dict,
        burp_metrics: Dict
    ) -> Dict:
        """
        Run all statistical tests and generate thesis-ready output.
        """
        print(f"\n   STATISTICAL SIGNIFICANCE TESTS ")

        # Build detection vectors from metrics
        # Each position represents one OWASP category (API1-API10)
        astra_vec = self._metrics_to_vector(astra_metrics)
        zap_vec = self._metrics_to_vector(zap_metrics)
        burp_vec = self._metrics_to_vector(burp_metrics)

        # McNemar's tests
        print(f"\n  [*] ASTRA vs OWASP ZAP:")
        astra_vs_zap = self.mcnemar_test(astra_vec, zap_vec, "ASTRA", "ZAP")

        print(f"\n  [*] ASTRA vs Burp Suite:")
        astra_vs_burp = self.mcnemar_test(astra_vec, burp_vec, "ASTRA", "Burp")

        # Effect sizes
        astra_recall = astra_metrics.get("recall_pct", 0)
        zap_recall = zap_metrics.get("recall_pct", 0)
        burp_recall = burp_metrics.get("recall_pct", 0)

        effect_vs_zap = self.effect_size(astra_recall, zap_recall)
        effect_vs_burp = self.effect_size(astra_recall, burp_recall)

        # Confidence intervals for ASTRA
        tp = astra_metrics.get("tp", 0)
        total = tp + astra_metrics.get("fn", 0)
        recall_ci = self.confidence_interval(tp, total)
        precision_ci = self.confidence_interval(tp, tp + astra_metrics.get("fp", 0))

        print(f"""
  
           STATISTICAL TEST SUMMARY                        
  
    ASTRA vs ZAP  : p={astra_vs_zap['p_value']} {'[OK] Significant' if astra_vs_zap['significant'] else '[X] Not Significant':<25}
    ASTRA vs Burp : p={astra_vs_burp['p_value']} {'[OK] Significant' if astra_vs_burp['significant'] else '[X] Not Significant':<25}
    Effect vs ZAP : h={effect_vs_zap['cohens_h']} ({effect_vs_zap['interpretation']:<25})
    Recall CI     : {recall_ci['proportion_pct']}% [{recall_ci['lower_pct']}%, {recall_ci['upper_pct']}%] 95% CI           
    Precision CI  : {precision_ci['proportion_pct']}% [{precision_ci['lower_pct']}%, {precision_ci['upper_pct']}%] 95% CI           
  """)

        return {
            "astra_vs_zap": astra_vs_zap,
            "astra_vs_burp": astra_vs_burp,
            "effect_size_vs_zap": effect_vs_zap,
            "effect_size_vs_burp": effect_vs_burp,
            "recall_confidence_interval": recall_ci,
            "precision_confidence_interval": precision_ci,
        }

    def _metrics_to_vector(self, metrics: Dict) -> List[bool]:
        """Convert metrics dict to binary detection vector."""
        detected = set(metrics.get("detected_ids", []))
        all_cats = [f"API{i}:2023" for i in range(1, 11)]
        return [cat in detected for cat in all_cats]

    def _chi2_p_value(self, chi2: float, df: int = 1) -> float:
        """Approximate p-value from chi-squared statistic."""
        # Approximation for df=1
        if chi2 >= 10.83:   return 0.001
        if chi2 >= 6.63:    return 0.01
        if chi2 >= 3.84:    return 0.05
        if chi2 >= 2.71:    return 0.10
        if chi2 >= 1.32:    return 0.25
        return 0.50

    def _generate_thesis_statement(
        self, tool_a, tool_b, significant, b, c, p_value
    ) -> str:
        if significant:
            return (
                f"McNemar's test confirms that {tool_a} detects significantly more "
                f"OWASP API Top 10 vulnerabilities than {tool_b} "
                f"(χ²={round((abs(b-c)-1)**2/(b+c) if b+c>0 else 0, 2)}, "
                f"p={p_value}, α=0.05). "
                f"{tool_a} uniquely detected {b} vulnerability categories "
                f"that {tool_b} missed, while {tool_b} uniquely detected {c} "
                f"that {tool_a} missed."
            )
        else:
            return (
                f"McNemar's test found no statistically significant difference "
                f"between {tool_a} and {tool_b} (p={p_value}, α=0.05), "
                f"though {tool_a} detected {b} additional categories."
            )

    def _print_result(self, result: Dict):
        sig = "[OK] SIGNIFICANT" if result["significant"] else "[X] NOT SIGNIFICANT"
        print(f"""
  McNemar's Test: {result['tool_a']} vs {result['tool_b']}
  
  Chi²      : {result['chi2_statistic']}
  p-value   : {result['p_value']}
  Result    : {sig} (α={result['alpha']})
  Statement : {result['interpretation']}""")
