import json
import time
from datetime import datetime

from network_info import get_network_details
from port_info import scan_ports
from vuln_detect import analyze_devices, print_assessment_report
from database import save_scan_to_db
from report_gen import generate_html_report


def run_full_security_assessment(top_ports=100, save_output=True):
    start_time = time.time()
    scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "=" * 65)
    print("      NETWORK VULNERABILITY SCANNER & RISK ASSESSMENT")
    print(f"               Scan Time: {scan_timestamp}")
    print("=" * 65)

    # 1. NETWORK & HOST DISCOVERY
    print("\n[PHASE 1] Detecting Network Environment & Reachable Devices...")
    net_info, discovered_hosts = get_network_details()

    if not net_info or not discovered_hosts:
        print("[!] Error: No active network interface or reachable hosts found.")
        return None

    print(f"  Interface:  {net_info['interface']}")
    print(f"  Local IP:   {net_info['ip_address']}")
    print(f"  Subnet:     {net_info['subnet']}")
    print(f"  Gateway:    {net_info['gateway']}")
    print(f"  Found {len(discovered_hosts)} reachable host(s): {', '.join(discovered_hosts)}")

    # 2. PORT & SERVICE FINGERPRINTING
    print(f"\n[PHASE 2] Auditing Exposed Ports & Services (Top {top_ports} Ports)...")
    scan_data = scan_ports(discovered_hosts, top_ports=top_ports)
    
    total_open_ports = sum(len(h.get("ports", [])) for h in scan_data)
    print(f"  Completed port scan. Found {total_open_ports} open port(s) across target(s).")

    # 3. VULNERABILITY DETECTION & RISK SCORING
    print("\n[PHASE 3] Correlating Vulnerabilities, Policy Risks & CVSS Scores...")
    assessment = analyze_devices(scan_data)

    # 4. PRINT REPORT SUMMARY TO CONSOLE
    print_assessment_report(assessment)

    # 5. COMPILE FULL AUDIT RECORD
    elapsed = round(time.time() - start_time, 2)
    audit_snapshot = {
        "timestamp": scan_timestamp,
        "elapsed_seconds": elapsed,
        "network_info": net_info,
        "discovered_hosts": discovered_hosts,
        "assessment_results": assessment
    }

    if save_output:
        # Save JSON snapshot
        with open("network_security_output.json", "w") as f:
            json.dump(audit_snapshot, f, indent=2)

        # Save to SQLite Database
        scan_id = save_scan_to_db(audit_snapshot)
        print(f"[✓] Saved scan record to SQLite (Scan ID: #{scan_id})")

        # Auto-generate formal HTML Security Report
        generate_html_report(audit_snapshot, output_filename="security_audit_report.html")

    return audit_snapshot


def main():
    run_full_security_assessment(top_ports=100)


if __name__ == "__main__":
    main()
