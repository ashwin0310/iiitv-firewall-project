import json
import os
import time
from datetime import datetime

from network_info import get_network_details
from port_info import scan_ports
from vuln_detect import analyze_devices, print_assessment_report

STATE_FILE = "network_state.json"
HISTORY_FILE = "scan_history.json"


def load_previous_state():
    """Loads the last recorded network baseline state from disk."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def save_current_state(current_state):
    """Saves the current state and appends it to the historical audit log."""
    # 1. Update latest baseline
    with open(STATE_FILE, "w") as f:
        json.dump(current_state, f, indent=2)

    # 2. Append to scan history
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except Exception:
            history = []

    history.append({
        "timestamp": current_state["timestamp"],
        "subnet": current_state["network_info"].get("subnet"),
        "total_hosts": len(current_state["discovered_hosts"]),
        "hosts": current_state["discovered_hosts"]
    })

    # Keep last 50 historical records to prevent uncontrolled file growth
    history = history[-50:]
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def detect_network_changes(prev_state, curr_state):
    """
    Differential Analysis Engine:
    Compares previous baseline vs current snapshot.
    Identifies:
      - Subnet / gateway migration
      - Newly joined hosts
      - Disconnected hosts
      - Newly opened or closed ports
      - Security posture changes
    """
    alerts = []

    if not prev_state:
        alerts.append({
            "level": "INFO",
            "category": "BASELINE",
            "message": "Baseline network profile established. Monitoring initialized."
        })
        return alerts

    prev_net = prev_state.get("network_info", {})
    curr_net = curr_state.get("network_info", {})

    # 1. Subnet / Network Environment Migration Check
    if prev_net.get("subnet") != curr_net.get("subnet"):
        alerts.append({
            "level": "WARNING",
            "category": "NETWORK_MIGRATION",
            "message": f"Network subnet changed from {prev_net.get('subnet')} to {curr_net.get('subnet')}!"
        })

    if prev_net.get("gateway") != curr_net.get("gateway"):
        alerts.append({
            "level": "WARNING",
            "category": "GATEWAY_CHANGE",
            "message": f"Default gateway changed from {prev_net.get('gateway')} to {curr_net.get('gateway')}."
        })

    # 2. Host Membership Delta
    prev_hosts = set(prev_state.get("discovered_hosts", []))
    curr_hosts = set(curr_state.get("discovered_hosts", []))

    new_hosts = curr_hosts - prev_hosts
    for host in new_hosts:
        alerts.append({
            "level": "HIGH",
            "category": "NEW_DEVICE",
            "message": f"New device joined the network: {host}"
        })

    dropped_hosts = prev_hosts - curr_hosts
    for host in dropped_hosts:
        alerts.append({
            "level": "INFO",
            "category": "DEVICE_OFFLINE",
            "message": f"Device disconnected or became unreachable: {host}"
        })

    # 3. Port & Service Exposure Delta
    prev_assessments = {h["ip"]: h for h in prev_state.get("assessment_results", [])}
    curr_assessments = {h["ip"]: h for h in curr_state.get("assessment_results", [])}

    for ip, curr_host in curr_assessments.items():
        if ip in prev_assessments:
            prev_ports = {f"{p['port']}/{p['service']}" for p in prev_assessments[ip].get("findings", [])}
            curr_ports = {f"{p['port']}/{p['service']}" for p in curr_host.get("findings", [])}

            # Newly discovered exposed ports/vulnerabilities
            new_vulns = curr_ports - prev_ports
            for vuln_desc in new_vulns:
                alerts.append({
                    "level": "CRITICAL",
                    "category": "NEW_PORT_EXPOSED",
                    "message": f"[{ip}] Newly exposed service or vulnerability detected: {vuln_desc}"
                })

            # Check for score drop
            prev_score = prev_assessments[ip].get("security_score", 100)
            curr_score = curr_host.get("security_score", 100)
            if curr_score < prev_score:
                alerts.append({
                    "level": "HIGH",
                    "category": "POSTURE_DEGRADED",
                    "message": f"[{ip}] Security score degraded from {prev_score} to {curr_score}!"
                })

    return alerts


def print_alerts(alerts):
    """Formats and prints real-time alerts."""
    if not alerts:
        print("  [✓] No changes detected. Network posture is stable.")
        return

    print("\n" + "!" * 60)
    print("                 SECURITY ALERTS DETECTED")
    print("!" * 60)
    for alert in alerts:
        badge = f"[{alert['level']}]"
        print(f"  {badge:<10} [{alert['category']}] {alert['message']}")
    print("!" * 60 + "\n")


def run_monitor_cycle(top_ports=100):
    """Executes a single monitoring snapshot and calculates delta against baseline."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{timestamp}] Running Network Health & State Check...")

    # Discover network & hosts
    net_info, discovered_hosts = get_network_details()
    if not net_info:
        print("  [!] Error: Unable to detect network interface.")
        return

    # Port audit
    scan_data = scan_ports(discovered_hosts, top_ports=top_ports)

    # Vulnerability & Risk analysis
    assessment = analyze_devices(scan_data)

    current_state = {
        "timestamp": timestamp,
        "network_info": net_info,
        "discovered_hosts": discovered_hosts,
        "assessment_results": assessment
    }

    # Compare against previous baseline
    prev_state = load_previous_state()
    alerts = detect_network_changes(prev_state, current_state)
    print_alerts(alerts)

    # Save new state as current baseline
    save_current_state(current_state)


def start_monitoring_loop(interval_seconds=30):
    """Runs continuous real-time monitoring loop every N seconds."""
    print("=" * 65)
    print(f"Starting Continuous Real-Time Network Monitor (Interval: {interval_seconds}s)")
    print("Press Ctrl+C to stop.")
    print("=" * 65)

    try:
        while True:
            run_monitor_cycle()
            print(f"Waiting {interval_seconds} seconds until next scan cycle...\n")
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")


if __name__ == "__main__":
    start_monitoring_loop(interval_seconds=30)

