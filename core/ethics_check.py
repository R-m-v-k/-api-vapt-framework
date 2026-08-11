# ethics_check.py
# Authorization confirmation module
# ASTRA Framework

import datetime
import os

DISCLAIMER = """

              ASTRA  LEGAL DISCLAIMER                       

  This tool is intended for AUTHORIZED security testing      
  only. Unauthorized use against systems you do not own      
  or have explicit written permission to test is:            
                                                             
    Illegal under the Computer Misuse Act (UK/Ireland)      
    Illegal under the CFAA (USA)                            
    Illegal under EU Directive 2013/40/EU                   
                                                             
  By proceeding, you confirm that:                           
   1. You own the target system, OR                          
   2. You have explicit written authorization to test it     
   3. You accept full legal responsibility for this scan     

"""


def run_ethics_check(target_url: str, output_dir: str = "./reports") -> bool:
    """
    Displays legal disclaimer and requires explicit confirmation.
    Logs the authorization acknowledgment with timestamp.
    Returns True if authorized, False if declined.
    """
    print(DISCLAIMER)
    print(f"  Target URL : {target_url}")
    print(f"  Timestamp  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    response = input("  Do you have authorization to test this target? (yes/no): ").strip().lower()

    if response != "yes":
        print("\n  [!] Scan aborted. Authorization not confirmed.")
        return False

    # Log the confirmation
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, "authorization_log.txt")
    with open(log_path, "a") as f:
        f.write(
            f"{datetime.datetime.now().isoformat()} | "
            f"TARGET: {target_url} | "
            f"AUTHORIZED: YES\n"
        )

    print(f"\n  [+] Authorization confirmed. Log saved to {log_path}")
    print("  [*] Starting ASTRA scan...\n")
    return True
