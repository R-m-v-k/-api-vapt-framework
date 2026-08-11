# modules/api1_bola.py  FULLY GENERALISED v2.0
# API1:2023  Broken Object Level Authorization (BOLA)
#
# Generalisation:
#   Works on any REST API by:
#   1. Auto-detecting ID-bearing endpoints from OpenAPI spec
#   2. Creating resources as User A, accessing as User B
#   3. Probing sequential numeric IDs (1,2,3...)
#   4. Probing UUID patterns discovered in responses
#   5. Using differential response analysis
#
#   For crAPI: uses known endpoint patterns
#   For any target: uses discovered endpoints + generic patterns

from modules.base_module import BaseModule, Finding
from core.differential_analyser import DifferentialAnalyser
from typing import List, Dict, Optional
import re
import json


class BOLAModule(BaseModule):

    OWASP_ID = "API1:2023"
    OWASP_NAME = "Broken Object Level Authorization"

    # Generic ID patterns to test on any API
    GENERIC_ID_PATHS = [
        "/api/v1/users/{id}",    "/api/v2/users/{id}",
        "/api/users/{id}",       "/users/{id}",
        "/api/v1/profile/{id}",  "/profile/{id}",
        "/api/v1/account/{id}",  "/account/{id}",
        "/api/v1/orders/{id}",   "/orders/{id}",
        "/api/v1/items/{id}",    "/items/{id}",
        "/api/v1/posts/{id}",    "/posts/{id}",
        "/api/v1/products/{id}", "/products/{id}",
        "/api/v1/vehicles/{id}", "/vehicles/{id}",
        "/api/v1/documents/{id}","/documents/{id}",
        "/api/v1/files/{id}",    "/files/{id}",
        "/api/v1/messages/{id}", "/messages/{id}",
        "/api/v1/customers/{id}","/customers/{id}",
        "/api/v1/records/{id}",  "/records/{id}",
    ]

    def run(self, endpoints=None) -> List[Finding]:
        print(f"\n   {self.OWASP_ID}  {self.OWASP_NAME} ")

        token_a = self.auth.get_token("user_a")
        token_b = self.auth.get_token("user_b")

        if not token_a or not token_b:
            print("  [!] BOLA requires User A + User B tokens  skipping")
            return self.findings

        target_type = self.config.target.target_type

        # Always run generic test first
        self._test_generic_bola(token_a, token_b, endpoints)

        # Then run target-specific tests if applicable
        if target_type == "crapi":
            self._test_crapi_bola(token_a, token_b)

        if not self.findings:
            print("  [+] No BOLA vulnerabilities detected")

        return self.findings

    #  GENERIC BOLA (works on any API) 

    def _test_generic_bola(self, token_a: str, token_b: str, endpoints=None):
        """
        Generic BOLA detection  works on any API.
        Strategy:
          1. From spec-discovered endpoints with ID params
          2. From hardcoded common path patterns
          3. From IDs discovered in User A's responses
        """
        print("  [*] Running generic BOLA tests...")
        analyser = DifferentialAnalyser()
        tested = set()

        # Collect ID-bearing endpoints
        id_endpoints = []

        # From OpenAPI spec discovery
        if endpoints:
            for ep in endpoints:
                path = ep.get("path", "")
                method = ep.get("method", "GET")
                if method == "GET" and re.search(r'\{[^}]+\}', path):
                    id_endpoints.append(path)

        # Add generic common paths
        id_endpoints.extend(self.GENERIC_ID_PATHS)

        # Get IDs from config
        test_ids = self.config.scanning.bola_test_ids or [1, 2, 3, 4, 5]

        for path_template in id_endpoints[:20]:
            for test_id in test_ids[:3]:
                # Replace {id} placeholder with actual ID
                test_path = re.sub(r'\{[^}]+\}', str(test_id), path_template)

                if test_path in tested:
                    continue
                tested.add(test_path)

                # Check endpoint exists at all (User A)
                resp_a = self.requester.get(test_path, token=token_a)
                if not resp_a or resp_a.status_code not in [200, 201]:
                    continue

                # Now try with User B
                resp_b = self.requester.get(test_path, token=token_b)
                if not resp_b or resp_b.status_code not in [200, 201]:
                    continue

                # Differential analysis  did User B get real data?
                try:
                    data_a = resp_a.json()
                    data_b = resp_b.json()
                except Exception:
                    continue

                # Get user identities for ownership check
                owner_identity = {
                    "email": self.config.target.user_a.email,
                    "id": str(test_id),
                }
                requester_identity = {
                    "email": self.config.target.user_b.email,
                }

                analysis = analyser.analyse(data_a, data_b, owner_identity, requester_identity)

                # High confidence = definite BOLA
                if analysis["bola_confirmed"] and analysis["confidence"] in ["Critical", "High"]:
                    self.add_finding(
                        title=f"BOLA  Cross-user data access via {test_path}",
                        severity="Critical",
                        endpoint=test_path,
                        method="GET",
                        evidence={
                            "path_template": path_template,
                            "test_id": test_id,
                            "user_a": self.config.target.user_a.email,
                            "user_b": self.config.target.user_b.email,
                            "token_used": "User B token",
                            "response_status": resp_b.status_code,
                            "similarity_score": analysis["similarity_score"],
                            "ownership_mismatch": analysis["ownership_mismatch"],
                            "sensitive_fields_exposed": analysis["sensitive_fields_exposed"],
                            "differential_analysis": analysis["evidence"],
                            "expected": "403 Forbidden for User B",
                            "actual": f"{resp_b.status_code} OK  data returned",
                        },
                        description=(
                            f"Endpoint {test_path} returns data to any authenticated user "
                            f"regardless of resource ownership. User B accessed an object "
                            f"belonging to User A without authorization check."
                        ),
                        remediation=(
                            "Implement object-level authorization. Before returning any "
                            "resource, verify: does the requesting user own this object? "
                            "Return HTTP 403 if ownership check fails."
                        ),
                        confidence=analysis["confidence"],
                    )
                    self.print_finding(self.findings[-1])
                    break  # Found BOLA on this template, move to next

                # Medium confidence  still flag but lower severity
                elif analysis["similarity_score"] > 0.8 and resp_b.status_code == 200:
                    self.add_finding(
                        title=f"BOLA (Potential)  Same data returned to different users at {test_path}",
                        severity="High",
                        endpoint=test_path,
                        method="GET",
                        evidence={
                            "path": test_path,
                            "similarity_score": analysis["similarity_score"],
                            "user_b_status": resp_b.status_code,
                            "note": "High response similarity between users suggests no ownership enforcement",
                            "expected": "Different data or 403 per user",
                        },
                        description=f"Endpoint {test_path} may not enforce object-level authorization.",
                        remediation="Review ownership validation on this endpoint.",
                        confidence="Medium",
                    )
                    self.print_finding(self.findings[-1])

        # Also try to create a resource and replay
        self._test_create_and_replay(token_a, token_b, endpoints)

    def _test_create_and_replay(self, token_a: str, token_b: str, endpoints=None):
        """
        Asemi (2023) pattern:
        Create resource as User A -> capture ID -> replay as User B
        Works on any API with POST + GET endpoints.
        """
        if not endpoints:
            return

        # Find POST endpoints that likely create resources
        create_endpoints = [
            ep for ep in endpoints
            if ep.get("method") == "POST"
            and not any(skip in ep.get("path","").lower()
                       for skip in ["login","auth","logout","token","password"])
        ]

        for ep in create_endpoints[:5]:
            path = ep.get("path", "")
            print(f"  [*] Testing create-and-replay BOLA on {path}...")

            # Try to create a resource as User A
            resp_create = self.requester.post(
                path, body={"name": "astra_test", "title": "ASTRA Test",
                            "content": "Security test by ASTRA"},
                token=token_a
            )

            if not resp_create or resp_create.status_code not in [200, 201]:
                continue

            # Extract resource ID from response
            resource_id = None
            try:
                data = resp_create.json()
                for id_field in ["id", "_id", "uuid", "ID", "postId",
                                  "orderId", "itemId", "resourceId"]:
                    if data.get(id_field):
                        resource_id = str(data[id_field])
                        break
            except Exception:
                continue

            if not resource_id:
                continue

            print(f"  [+] Created resource ID: {resource_id}")

            # Construct GET path
            get_path = path.rstrip("/") + "/" + resource_id

            # Try to access as User B
            resp_b = self.requester.get(get_path, token=token_b)

            if resp_b and resp_b.status_code == 200:
                self.add_finding(
                    title=f"BOLA  User A created resource accessible by User B at {get_path}",
                    severity="Critical",
                    endpoint=get_path,
                    method="GET",
                    evidence={
                        "create_endpoint": path,
                        "resource_id": resource_id,
                        "created_by": self.config.target.user_a.email,
                        "accessed_by": self.config.target.user_b.email,
                        "token_used": "User B token",
                        "response_status": resp_b.status_code,
                        "expected": "403 Forbidden",
                        "actual": f"{resp_b.status_code} OK",
                        "method": "Create-and-replay (Asemi 2023)",
                    },
                    description=(
                        f"User A created a resource at {path}. "
                        f"User B can access it using only the resource ID. "
                        f"No ownership validation is performed."
                    ),
                    remediation=(
                        "Validate that the requesting user owns the resource "
                        "before returning it. Use server-side ownership records, "
                        "not client-supplied user IDs."
                    ),
                )
                self.print_finding(self.findings[-1])


    def _test_crapi_bola(self, token_a: str, token_b: str):
        """crAPI-specific BOLA tests  known endpoint patterns."""
        print("  [*] Testing crAPI-specific BOLA patterns...")

        post_id = self._create_crapi_post(token_a)
        if post_id:
            resp_b = self.requester.get(
                f"/community/api/v2/community/posts/{post_id}", token=token_b
            )
            if resp_b and resp_b.status_code == 200:
                self.add_finding(
                    title="BOLA  Cross-user community post access (crAPI)",
                    severity="Critical",
                    endpoint=f"/community/api/v2/community/posts/{post_id}",
                    method="GET",
                    evidence={
                        "post_id": post_id,
                        "owner": self.config.target.user_a.email,
                        "accessed_by": self.config.target.user_b.email,
                        "response_status": resp_b.status_code,
                        "expected": "403 Forbidden",
                        "actual": f"{resp_b.status_code} OK",
                    },
                    description="Any authenticated user can access any community post by ID.",
                    remediation="Validate post ownership before returning data.",
                )
                self.print_finding(self.findings[-1])

        self._test_crapi_vehicle_location(token_a, token_b)
        self._test_crapi_videos(token_a, token_b)
        self._test_crapi_reports(token_a, token_b)

    def _create_crapi_post(self, token_a: str) -> Optional[str]:
        vehicles_resp = self.requester.get("/identity/api/v2/vehicle/vehicles", token=token_a)
        vehicle_uuid = None
        if vehicles_resp and vehicles_resp.status_code == 200:
            try:
                vehicles = vehicles_resp.json()
                if vehicles:
                    vehicle_uuid = vehicles[0].get("uuid") or str(vehicles[0].get("id", ""))
            except Exception:
                pass

        payload = {"content": "ASTRA security test post"}
        if vehicle_uuid:
            payload["vehicleId"] = vehicle_uuid

        resp = self.requester.post("/community/api/v2/community/posts",
                                   body=payload, token=token_a)
        if resp and resp.status_code in [200, 201]:
            try:
                data = resp.json()
                post_id = str(data.get("id") or data.get("_id") or data.get("postId") or "")
                if post_id:
                    print(f"  [+] Created post ID: {post_id}")
                    return post_id
            except Exception:
                pass
        return None

    def _test_crapi_vehicle_location(self, token_a: str, token_b: str):
        print("  [*] Testing BOLA on vehicle locations...")
        vehicles_resp = self.requester.get("/identity/api/v2/vehicle/vehicles", token=token_a)
        if not vehicles_resp or vehicles_resp.status_code != 200:
            return
        try:
            vehicles = vehicles_resp.json()
            if not vehicles:
                return
            vid = vehicles[0].get("uuid") or str(vehicles[0].get("id", ""))
            if not vid:
                return
            resp = self.requester.get(f"/identity/api/v2/vehicle/{vid}/location", token=token_b)
            if resp and resp.status_code == 200:
                self.add_finding(
                    title="BOLA  Cross-user vehicle location access",
                    severity="Critical",
                    endpoint=f"/identity/api/v2/vehicle/{vid}/location",
                    method="GET",
                    evidence={
                        "vehicle_id": vid,
                        "token_used": "User B token",
                        "response_status": resp.status_code,
                        "expected": "403 Forbidden",
                        "actual": f"{resp.status_code} OK",
                    },
                    description="Vehicle location accessible by any user with the vehicle ID.",
                    remediation="Verify vehicle ownership before returning location.",
                )
                self.print_finding(self.findings[-1])
        except Exception as e:
            print(f"  [!] Vehicle BOLA error: {e}")

    def _test_crapi_videos(self, token_a: str, token_b: str):
        print("  [*] Testing BOLA on user profile videos...")
        resp_a = self.requester.get("/identity/api/v2/user/dashboard", token=token_a)
        resp_b_dash = self.requester.get("/identity/api/v2/user/dashboard", token=token_b)
        if not resp_a or resp_a.status_code != 200:
            return
        try:
            video_id_a = resp_a.json().get("video_id")
            video_id_b = (resp_b_dash.json().get("video_id")
                         if resp_b_dash and resp_b_dash.status_code == 200 else None)
            if video_id_a and video_id_a != 0 and video_id_a != video_id_b:
                resp = self.requester.get(f"/identity/api/v2/user/videos/{video_id_a}", token=token_b)
                if resp and resp.status_code == 200:
                    self.add_finding(
                        title="BOLA  Cross-user profile video access",
                        severity="High",
                        endpoint=f"/identity/api/v2/user/videos/{video_id_a}",
                        method="GET",
                        evidence={"video_id": video_id_a, "token_used": "User B",
                                  "response_status": resp.status_code},
                        description="Profile video accessible by any user.",
                        remediation="Validate video ownership.",
                    )
                    self.print_finding(self.findings[-1])
        except Exception:
            pass

    def _test_crapi_reports(self, token_a: str, token_b: str):
        print("  [*] Testing BOLA on mechanic reports...")
        user_b_email = self.config.target.user_b.email if self.config.target.user_b else ""
        for report_id in range(1, 6):
            resp = self.requester.get("/workshop/api/mechanic/mechanic_report",
                                     token=token_b, params={"report_id": report_id})
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    report_email = (data.get("mechanic", {}).get("email", "") or
                                   data.get("created_by", ""))
                    if report_email and report_email != user_b_email:
                        self.add_finding(
                            title="BOLA  Cross-user mechanic report access",
                            severity="High",
                            endpoint=f"/workshop/api/mechanic/mechanic_report?report_id={report_id}",
                            method="GET",
                            evidence={"report_id": report_id, "owner": report_email,
                                     "accessed_by": user_b_email},
                            description="Mechanic report accessible by any authenticated user.",
                            remediation="Validate report ownership.",
                        )
                        self.print_finding(self.findings[-1])
                        break
                except Exception:
                    continue
