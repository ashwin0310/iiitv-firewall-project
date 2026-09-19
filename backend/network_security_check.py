import socket
import json

# Common risky ports and their severity
RISKY_PORTS = {
    21: ("FTP", "Medium"),
    23: ("Telnet", "High"),
    80: ("HTTP", "Medium"),
    443: ("HTTPS", "Informational"),
    445: ("SMB", "Medium"),
    3389: ("RDP", "High"),
}

def check_port(host, port, timeout=1):
    """Try connecting to a port to see if it's open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def assess_gateway(gateway_ip):
    findings = []
    for port, (service, severity) in RISKY_PORTS.items():
        if check_port(gateway_ip, port):
            findings.append({
                "port": port,
                "service": service,
                "severity": severity,
                "status": "Open"
            })
    return findings

def main():
    # Example: replace with gateway from network_info.py
    gateway_ip = "10.0.2.2"

    print("NETWORK SECURITY CHECK")
    print("----------------------")
    print(f"Assessing gateway: {gateway_ip}")

    results = assess_gateway(gateway_ip)

    if results:
        for f in results:
            print(f"Port {f['port']} ({f['service']}) → {f['severity']}")
    else:
        print("No risky ports detected.")

    # Save results to JSON
    output = {
        "gateway": gateway_ip,
        "findings": results
    }
    with open("network_security_output.json", "w") as f:
        json.dump(output, f, indent=4)

    print("\nResults saved to network_security_output.json")

if __name__ == "__main__":
    main()
