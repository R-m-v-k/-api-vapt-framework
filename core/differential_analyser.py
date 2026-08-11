# core/differential_analyser.py
#
# Differential Response Analysis
# Based on Ishida et al. (2024) methodology
#
# How it works:
#   Instead of just checking status codes, this compares
#   the actual data returned to User A vs User B.
#   If User B receives data that clearly belongs to User A
#   (different user_id, email, name etc.) -> BOLA confirmed
#   with high confidence and low false positives.
#
# Where it is used:
#   Called by api1_bola.py after a cross-user access is detected
#   to provide richer evidence and reduce false positives.
#
# Academic justification:
#   Addresses limitation identified in Ishida et al. (2024):
#   "similarity-based comparisons can lead to incorrect
#   classification of valid shared-resource responses"
#   We solve this by field-level ownership analysis.

import json
from typing import Dict, Optional, Tuple
from difflib import SequenceMatcher


class DifferentialAnalyser:
    """
    Compares API responses from two different users to determine
    whether unauthorized data access (BOLA) has occurred.

    Implements three-level analysis:
    1. Status code comparison (basic)
    2. Field-level ownership analysis (advanced)
    3. Similarity scoring (Ishida et al. method)
    """

    # Fields that identify ownership of a resource
    OWNERSHIP_FIELDS = [
        "user_id", "owner_id", "author_id", "created_by",
        "email", "username", "phone", "account_number",
        "facebook_id", "id", "uuid", "owner",
    ]

    def analyse(
        self,
        response_owner: dict,
        response_requester: dict,
        owner_identity: dict,
        requester_identity: dict,
    ) -> Dict:
        """
        Core differential analysis.

        Args:
            response_owner:     API response when legitimate owner requests resource
            response_requester: API response when different user requests same resource
            owner_identity:     Known fields of the owner {email, id, etc.}
            requester_identity: Known fields of the requester {email, id, etc.}

        Returns:
            Analysis result with confidence score and evidence
        """
        result = {
            "bola_confirmed": False,
            "confidence": "Low",
            "confidence_score": 0.0,
            "similarity_score": 0.0,
            "ownership_mismatch": False,
            "sensitive_fields_exposed": [],
            "evidence": {},
            "method": "differential_response_analysis",
            "academic_reference": "Ishida et al. (2024) ICACT",
        }

        if not response_owner or not response_requester:
            return result

        #  Level 1: Similarity Score (Ishida et al.) 
        similarity = self._calculate_similarity(response_owner, response_requester)
        result["similarity_score"] = round(similarity, 3)

        # High similarity but different users = same data returned = BOLA
        if similarity > 0.7:
            result["bola_confirmed"] = True
            result["confidence_score"] += 0.4
            result["evidence"]["similarity_analysis"] = (
                f"Similarity score {similarity:.2%}  requester received "
                f"near-identical data to owner's resource"
            )

        #  Level 2: Ownership Field Analysis 
        ownership_mismatch = self._check_ownership_fields(
            response_requester, owner_identity, requester_identity
        )
        result["ownership_mismatch"] = ownership_mismatch["found"]
        result["sensitive_fields_exposed"] = ownership_mismatch["fields"]

        if ownership_mismatch["found"]:
            result["bola_confirmed"] = True
            result["confidence_score"] += 0.5
            result["evidence"]["ownership_analysis"] = (
                f"Response contains owner's identifying fields: "
                f"{ownership_mismatch['fields']}  "
                f"requester received another user's data"
            )

        #  Level 3: Data Exposure Scoring 
        sensitive_count = len(ownership_mismatch["fields"])
        if sensitive_count >= 3:
            result["confidence_score"] += 0.1

        #  Final Confidence Rating 
        score = result["confidence_score"]
        if score >= 0.8:
            result["confidence"] = "Critical"
        elif score >= 0.6:
            result["confidence"] = "High"
        elif score >= 0.4:
            result["confidence"] = "Medium"
        else:
            result["confidence"] = "Low"

        result["evidence"]["summary"] = (
            f"Differential analysis: similarity={similarity:.2%}, "
            f"ownership_mismatch={ownership_mismatch['found']}, "
            f"sensitive_fields={sensitive_count}, "
            f"confidence={result['confidence']}"
        )

        return result

    def _calculate_similarity(self, resp_a: dict, resp_b: dict) -> float:
        """
        Calculate structural and content similarity between two responses.
        High similarity with different users = same data = BOLA.
        """
        try:
            str_a = json.dumps(resp_a, sort_keys=True, default=str)
            str_b = json.dumps(resp_b, sort_keys=True, default=str)
            return SequenceMatcher(None, str_a, str_b).ratio()
        except Exception:
            return 0.0

    def _check_ownership_fields(
        self,
        response: dict,
        owner_identity: dict,
        requester_identity: dict
    ) -> Dict:
        """
        Check if response contains owner's identifying data
        when accessed by a different user.

        Key insight: if response contains owner's email/id but
        was requested by a different user -> BOLA confirmed.
        """
        found_fields = []

        def search(obj, depth=0):
            if depth > 5:
                return
            if isinstance(obj, dict):
                for key, value in obj.items():
                    # Check if this is an ownership field
                    if any(f in key.lower() for f in self.OWNERSHIP_FIELDS):
                        str_val = str(value).lower()
                        # Check if value matches OWNER's identity (not requester)
                        for id_key, id_val in owner_identity.items():
                            if str(id_val).lower() in str_val and str_val:
                                # Also verify it DOESN'T match requester
                                requester_vals = [str(v).lower() for v in requester_identity.values()]
                                if str_val not in requester_vals:
                                    found_fields.append(f"{key}={value}")
                    search(value, depth + 1)
            elif isinstance(obj, list):
                for item in obj[:3]:
                    search(item, depth + 1)

        search(response)
        return {
            "found": len(found_fields) > 0,
            "fields": list(set(found_fields)),
        }

    def compare_field_sets(self, resp_a: dict, resp_b: dict) -> Dict:
        """
        Compare what fields are present in both responses.
        Used for API3 excessive exposure detection.
        """
        if not isinstance(resp_a, dict) or not isinstance(resp_b, dict):
            return {}

        fields_a = set(resp_a.keys())
        fields_b = set(resp_b.keys())

        return {
            "only_in_a": list(fields_a - fields_b),
            "only_in_b": list(fields_b - fields_a),
            "in_both": list(fields_a & fields_b),
            "total_fields_a": len(fields_a),
            "total_fields_b": len(fields_b),
        }
