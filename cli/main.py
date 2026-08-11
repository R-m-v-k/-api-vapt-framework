#!/usr/bin/env python3
# cli/main.py  ASTRA Framework v2.0  GENERALISED

# Fix module path  add framework root to Python path
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def print_banner():
    print("""

                                                           
                      
                 
                       
                       
                             
                             
                                                           
   Automated Security Testing and Reporting for APIs      
   OWASP API Security Top 10 (2023)  |  v2.0.0            
   Generalised  Works on ANY REST API                    
                                                           

    """)


def parse_args():
    parser = argparse.ArgumentParser(
        description="ASTRA v2.0  Generalised OWASP API Top 10 VAPT Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:

  Scan a named target from config.yaml:
    python cli/main.py --target crapi
    python cli/main.py --target custom_api

  Scan ANY API by URL (no config.yaml needed):
    python cli/main.py \\
      --url http://localhost:8080 \\
      --auth-endpoint /api/auth/login \\
      --user-a alice@test.com --pass-a Pass@123 \\
      --user-b bob@test.com   --pass-b Pass@123

  Run specific modules only:
    python cli/main.py --target crapi --modules api1 api2 api5

  Add a new target to config.yaml, then:
    python cli/main.py --target my_new_api
        """
    )

    #  Target selection (two modes) 
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target", "-t",
        help="Named target from config.yaml (e.g. crapi, custom_api)"
    )
    target_group.add_argument(
        "--url", "-u",
        help="Direct URL of ANY API to scan (e.g. https://api.example.com)"
    )

    #  Direct URL mode options 
    parser.add_argument("--auth-endpoint",  default="/api/auth/login",
                        help="Login endpoint (default: /api/auth/login)")
    parser.add_argument("--user-a",         help="User A email")
    parser.add_argument("--pass-a",         help="User A password")
    parser.add_argument("--user-b",         help="User B email")
    parser.add_argument("--pass-b",         help="User B password")
    parser.add_argument("--admin-email",    help="Admin email (optional)")
    parser.add_argument("--admin-pass",     help="Admin password (optional)")
    parser.add_argument("--token-field",    default="token",
                        help="Token field name in login response (default: token)")
    parser.add_argument("--token-header",   default="Authorization",
                        help="HTTP header the target reads the token from "
                             "(default Authorization; e.g. token, x-access-token)")
    parser.add_argument("--token-prefix",   default="Bearer",
                        help="Auth header prefix (default: Bearer)")
    parser.add_argument("--auth-body",      default=None,
                        help='Custom auth body template e.g. \'{"username":"{email}","password":"{password}"}\'')
    parser.add_argument("--endpoints-file", "-e", default=None,
                        help="Path to a file listing the target's real routes when no "
                             "OpenAPI spec is served. Accepts a plain-text list (one "
                             "route per line, optionally 'METHOD /path id_param'), a JSON "
                             "list of paths or objects, or a Postman v2.1 collection export. "
                             "Merged with any served spec and light probing.")

    parser.add_argument("--config", "-c",   default="config.yaml",
                        help="Config file path (default: config.yaml)")
    parser.add_argument("--output", "-o",   default="./reports",
                        help="Output directory (default: ./reports)")
    parser.add_argument(
        "--modules", "-m",
        nargs="+",
        choices=["api1","api2","api3","api4","api5","api6","api7","api8","api9","api10","all"],
        default=["all"],
        help="Modules to run (default: all)"
    )
    parser.add_argument("--skip-ethics", action="store_true",
                        help="Skip ethics confirmation")
    parser.add_argument("--breach-validation", action="store_true",
                        help="Run breach scenario validation after scan")
    parser.add_argument("--list-targets", action="store_true",
                        help="List available targets in config.yaml and exit")

    return parser.parse_args()


def list_available_targets(config_path: str):
    """Print all targets defined in config.yaml."""
    try:
        import yaml
        with open(config_path) as f:
            raw = yaml.safe_load(f)
        targets = raw.get("targets", {})
        print(f"\n  Available targets in {config_path}:\n")
        for name, t in targets.items():
            print(f"    {name:<20} -> {t.get('base_url', 'N/A')}")
        print(f"\n  Usage: python cli/main.py --target <name>")
        print(f"  Or add a new target to {config_path} using the template.\n")
    except Exception as e:
        print(f"  [!] Cannot read config: {e}")
    sys.exit(0)


def run_scan(args):
    print_banner()

    # List targets if requested
    if args.list_targets:
        list_available_targets(args.config)

    if args.target:
        # Mode 1: Named target from config.yaml
        from core.config import load_config
        try:
            config = load_config(args.config, args.target)
            print(f"  Target     : {args.target} ({config.target.base_url})")
        except ValueError as e:
            print(f"\n  [!] {e}")
            print(f"\n  TIP: Use --list-targets to see available targets")
            print(f"  TIP: Use --url mode to scan any API directly\n")
            sys.exit(1)
        except Exception as e:
            print(f"\n  [!] Config error: {e}")
            sys.exit(1)
    else:
        # Mode 2: Direct URL  works on any API
        from core.config import build_config_from_args
        if not args.user_a or not args.pass_a or not args.user_b or not args.pass_b:
            print("\n  [!] --url mode requires --user-a --pass-a --user-b --pass-b")
            print("  Example:")
            print("    python cli/main.py \\")
            print("      --url https://api.example.com \\")
            print("      --auth-endpoint /api/auth/login \\")
            print("      --user-a alice@test.com --pass-a Pass@123 \\")
            print("      --user-b bob@test.com   --pass-b Pass@123\n")
            sys.exit(1)

        config = build_config_from_args(
            url=args.url,
            auth_endpoint=args.auth_endpoint,
            email_a=args.user_a, pass_a=args.pass_a,
            email_b=args.user_b, pass_b=args.pass_b,
            email_admin=args.admin_email, pass_admin=args.admin_pass,
            token_field=args.token_field,
            token_prefix=args.token_prefix,
            token_header=args.token_header,
            auth_body_template=args.auth_body,
        )
        print(f"  Target     : {args.url} (direct URL mode)")

    print(f"  Target Type: {config.target.target_type}")
    print(f"  Config     : {args.config}")
    print(f"  Output     : {args.output}\n")

    if not args.skip_ethics:
        from core.ethics_check import run_ethics_check
        if not run_ethics_check(config.target.base_url, args.output):
            sys.exit(0)

    scan_start = datetime.datetime.now()
    os.makedirs(args.output, exist_ok=True)

    from core.requester import Requester
    from core.auth_handler import AuthHandler
    from core.discovery import EndpointDiscovery
    from core.fp_filter import FPFilter, MetricsCalculator

    requester = Requester(
        base_url=config.target.base_url,
        timeout=config.scanning.timeout,
        retry_attempts=config.scanning.retry_attempts,
        token_header=getattr(config.target, "token_header", "Authorization"),
        token_prefix=config.target.token_prefix,
    )

    auth = AuthHandler(config.target)

    if not auth.initialize_sessions():
        print("  [!] Authentication failed  check credentials")
        print("  TIP: Verify the auth endpoint and token field name in config.yaml")
        sys.exit(1)

    print("\n   ENDPOINT DISCOVERY ")
    discovery = EndpointDiscovery(
        config.target.base_url,
        token=auth.token_a,
        openapi_paths=config.target.openapi_paths,
        token_header=getattr(config.target, "token_header", "Authorization"),
        token_prefix=config.target.token_prefix,
        endpoints_file=(args.endpoints_file
                        or getattr(config.target, "endpoints_file", None)),
    )
    endpoints = discovery.run(token=auth.token_a)

    from modules.api1_bola import BOLAModule
    from modules.api2_broken_auth import BrokenAuthModule
    from modules.api3_bopla import BOPLAModule
    from modules.api4_resource import ResourceConsumptionModule
    from modules.api5_bfla import BFLAModule
    from modules.api6_business import BusinessLogicModule
    from modules.api7_ssrf import SSRFModule
    from modules.api8_misconfig import MisconfigModule
    from modules.api9_api10 import InventoryModule
    from modules.api10_unsafe import UnsafeConsumptionModule

    module_map = {
        "api1": BOLAModule,        "api2": BrokenAuthModule,
        "api3": BOPLAModule,       "api4": ResourceConsumptionModule,
        "api5": BFLAModule,        "api6": BusinessLogicModule,
        "api7": SSRFModule,        "api8": MisconfigModule,
        "api9": InventoryModule,   "api10": UnsafeConsumptionModule,
    }

    run_all = "all" in args.modules
    modules_to_run = (
        ["api1","api2","api3","api4","api5","api6","api7","api8","api9","api10"]
        if run_all else args.modules
    )

    all_results = []
    total_findings = 0

    print("\n" + "="*62)
    print("  RUNNING OWASP API TOP 10 SCAN")
    print("="*62)

    for key in modules_to_run:
        if key in module_map:
            module = module_map[key](requester, auth, config)
            findings = module.run(endpoints=endpoints)
            result = module.get_results()
            all_results.append(result)
            total_findings += len(findings)

    scan_end = datetime.datetime.now()

    #  False Positive Filter 
    print("\n  [*] Running False Positive Filter...")
    all_raw = []
    for r in all_results:
        all_raw.extend(r.get("findings", []))

    fp_filter = FPFilter(
        base_url=config.target.base_url, token=auth.token_a,
        token_header=getattr(config.target, "token_header", "Authorization"),
        token_prefix=config.target.token_prefix,
    )
    filter_result = fp_filter.filter_findings(all_raw)

    print("\n  [*] Calculating Detection Metrics...")
    calc = MetricsCalculator()
    ground_truth = (
        calc.CRAPI_GROUND_TRUTH
        if config.target.target_type == "crapi"
        else calc.CUSTOM_API_GROUND_TRUTH
    )
    metrics = calc.calculate(
        findings=filter_result["verified"],
        ground_truth=ground_truth,
        tool_name="ASTRA",
    )

    print("\n" + "="*62)
    print("  GENERATING REPORTS")
    print("="*62)

    from reporting.report_generator import ReportGenerator
    reporter = ReportGenerator(output_dir=args.output)
    json_path, html_path, summary, coverage = reporter.generate(
        all_findings=all_results,
        target_url=config.target.base_url,
        scan_start=scan_start,
        scan_end=scan_end,
    )

    detected_count = sum(1 for c in coverage if c["detected"])
    duration = str(scan_end - scan_start).split(".")[0]

    print(f"""

                    SCAN COMPLETE                        

  Target     : {config.target.base_url:<42} 
  Duration   : {duration:<42} 
  Total      : {str(summary['total']) + ' findings':<42} 
  Critical   : {str(summary['critical']):<42} 
  High       : {str(summary['high']):<42} 
  Medium     : {str(summary['medium']):<42} 
  Coverage   : {str(detected_count) + '/10 OWASP API categories':<42} 

  Precision  : {str(metrics.get('precision_pct','N/A')) + '%':<42} 
  Recall     : {str(metrics.get('recall_pct','N/A')) + '%':<42} 
  F1 Score   : {str(metrics.get('f1_pct','N/A')) + '%':<42} 

  JSON Report: {str(json_path)[-42:]:<42} 
  HTML Report: {str(html_path)[-42:]:<42} 
""")

    if args.breach_validation:
        from validation.breach_scenarios import BreachValidator
        validator = BreachValidator(base_url=config.target.base_url)
        validator.run_all()

    return all_results


if __name__ == "__main__":
    args = parse_args()
    run_scan(args)
