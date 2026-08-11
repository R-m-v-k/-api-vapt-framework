# api6_business.py  FIXED
# API6:2023  Unrestricted Access to Sensitive Business Flows
# Fix: correct crAPI coupon endpoint and multiple coupon codes

from modules.base_module import BaseModule, Finding
from modules.generic_strategies import GenericStrategiesMixin
from typing import List


class BusinessLogicModule(GenericStrategiesMixin, BaseModule):
    OWASP_ID = "API6:2023"
    OWASP_NAME = "Unrestricted Access to Sensitive Business Flows"

    # crAPI known coupon codes from challenges
    CRAPI_COUPON_CODES = [
        "TRAC075", "CRACK1000", "DEAL1000",
        "PROMO75", "SAVE10", "FREE100",
    ]

    def run(self, endpoints=None) -> List[Finding]:
        print(f"\n   {self.OWASP_ID}  {self.OWASP_NAME} ")
        token_a = self.auth.get_token("user_a")
        if not token_a:
            return self.findings

        target_type = self.config.target.target_type

        if target_type == "crapi":
            self._test_crapi_coupon_abuse(token_a)
            self._test_crapi_bulk_order(token_a)
        elif target_type == "custom":
            self._test_custom_promo_abuse(token_a)

        # Generic endpoint-driven test  runs on any target
        self.generic_business_logic(endpoints, token_a)

        if not self.findings:
            print("  [+] No Business Logic vulnerabilities detected")
        return self.findings

    def _test_crapi_coupon_abuse(self, token: str):
        """Test crAPI coupon redemption  try multiple known codes."""
        print("  [*] Testing coupon abuse on crAPI...")

        # First find a valid coupon by trying known codes
        valid_coupon = None
        for code in self.CRAPI_COUPON_CODES:
            resp = self.requester.post(
                "/community/api/v2/coupon/validate-coupon",
                body={"coupon_code": code},
                token=token,
            )
            if resp and resp.status_code == 200:
                valid_coupon = code
                print(f"  [+] Found valid coupon: {code}")
                break

        if not valid_coupon:
            # Try the apply-coupon endpoint instead
            print("  [!] No valid coupon found via validate  trying apply endpoint...")
            self._test_crapi_apply_coupon(token)
            return

        # Try applying valid coupon multiple times
        results = []
        for i in range(3):
            resp = self.requester.post(
                "/community/api/v2/coupon/validate-coupon",
                body={"coupon_code": valid_coupon},
                token=token,
            )
            if resp:
                results.append(resp.status_code)

        if results.count(200) >= 2:
            self.add_finding(
                title="Business Logic  Coupon reusable multiple times",
                severity="High",
                endpoint="/community/api/v2/coupon/validate-coupon",
                method="POST",
                evidence={
                    "coupon_code": valid_coupon,
                    "attempts": 3,
                    "successful": results.count(200),
                    "status_codes": results,
                    "expected": "Only one successful redemption",
                    "actual": f"{results.count(200)} successful redemptions",
                },
                description="Coupon code can be validated/redeemed multiple times by same user.",
                remediation="Track coupon redemption per user. Invalidate after first use.",
            )
            self.print_finding(self.findings[-1])

    def _test_crapi_apply_coupon(self, token: str):
        """Alternative coupon test via shop endpoints."""
        # Try getting available products first
        resp = self.requester.get("/workshop/api/shop/products", token=token)
        if not resp or resp.status_code != 200:
            return

        try:
            products = resp.json()
            if not products:
                return

            product_id = None
            if isinstance(products, list) and products:
                product_id = products[0].get("id")
            elif isinstance(products, dict):
                items = products.get("products", products.get("items", []))
                if items:
                    product_id = items[0].get("id")

            if not product_id:
                return

            # Try buying same product twice (business logic flaw)
            results = []
            for _ in range(2):
                r = self.requester.post(
                    "/workshop/api/shop/orders",
                    body={"product_id": product_id, "quantity": 1},
                    token=token,
                )
                if r:
                    results.append(r.status_code)

            if results.count(200) >= 2:
                self.add_finding(
                    title="Business Logic  Multiple orders without balance check",
                    severity="High",
                    endpoint="/workshop/api/shop/orders",
                    method="POST",
                    evidence={
                        "product_id": product_id,
                        "attempts": 2,
                        "successful": results.count(200),
                        "status_codes": results,
                    },
                    description="Shop allows multiple orders without proper balance validation.",
                    remediation="Validate user balance before each order. Prevent duplicate orders.",
                )
                self.print_finding(self.findings[-1])

        except Exception as e:
            print(f"  [!] Apply coupon test error: {e}")

    def _test_crapi_bulk_order(self, token: str):
        """Test for negative quantity order (business logic abuse)."""
        print("  [*] Testing negative quantity order (business logic)...")

        # Get product first
        resp = self.requester.get("/workshop/api/shop/products", token=token)
        if not resp or resp.status_code != 200:
            return

        try:
            products = resp.json()
            product_id = None
            if isinstance(products, list) and products:
                product_id = products[0].get("id")
            elif isinstance(products, dict):
                items = products.get("products", products.get("items", []))
                if items:
                    product_id = items[0].get("id")

            if not product_id:
                return

            # Try negative quantity  should fail but may add credit
            resp_neg = self.requester.post(
                "/workshop/api/shop/orders",
                body={"product_id": product_id, "quantity": -1},
                token=token,
            )

            if resp_neg and resp_neg.status_code == 200:
                self.add_finding(
                    title="Business Logic  Negative quantity order accepted",
                    severity="Critical",
                    endpoint="/workshop/api/shop/orders",
                    method="POST",
                    evidence={
                        "product_id": product_id,
                        "quantity_sent": -1,
                        "response_status": resp_neg.status_code,
                        "response_preview": str(resp_neg.text)[:200],
                        "expected": "400 Bad Request",
                        "actual": f"{resp_neg.status_code} OK",
                    },
                    description=(
                        "Order endpoint accepts negative quantities which may "
                        "result in credit being added to the user account."
                    ),
                    remediation=(
                        "Validate that quantity is a positive integer. "
                        "Reject orders with quantity <= 0."
                    ),
                )
                self.print_finding(self.findings[-1])

        except Exception as e:
            print(f"  [!] Negative quantity test error: {e}")

    def _test_custom_promo_abuse(self, token: str):
        print("  [*] Testing promo code reuse on Custom API...")
        payload = {"code": "FREE", "rental_id": 1}
        results = []
        for _ in range(3):
            resp = self.requester.post("/rentals/promo", body=payload, token=token)
            if resp:
                results.append(resp.status_code)

        if results.count(200) >= 2:
            self.add_finding(
                title="Business Logic  FREE promo code reusable unlimited times",
                severity="Critical",
                endpoint="/rentals/promo",
                method="POST",
                evidence={
                    "code_used": "FREE",
                    "discount": "100%",
                    "attempts": 3,
                    "successful": results.count(200),
                    "expected": "One use per user",
                    "actual": f"{results.count(200)}/3 uses succeeded",
                },
                description="FREE promo code (100% discount) can be applied unlimited times.",
                remediation="Track per-user promo usage. Enforce single redemption per user per code.",
            )
            self.print_finding(self.findings[-1])
