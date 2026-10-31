import requests
import json

# Security Policy & Misconfiguration Knowledge Base
PORT_POLICY_RULES = {
    21: {
        "service": "FTP",
        "severity": "High",
        "title": "Unencrypted File Transfer Protocol (FTP) Exposed",
        "description": "FTP transmits credentials and file data in cleartext, exposing them to sniffing and MITM attacks.",
        "remediation": "Disable plain FTP and replace with SFTP (SSH File Transfer Protocol) or FTPS."
    },
    23: {
        "service": "Telnet",
        "severity": "Critical",
        "title": "Insecure Remote Terminal (Telnet) Detected",
        "description": "Telnet transmits all sessions, including usernames and passwords, in unencrypted cleartext.",
        "remediation": "Immediately disable the Telnet service and enforce SSH (Port 22) for all remote administration."
    },
    80: {
        "service": "HTTP",
        "severity": "Low",
        "title": "Unencrypted HTTP Service Exposed",
        "description": "Web traffic is transmitted in plaintext without TLS encryption.",
        "remediation": "Implement TLS/SSL certificates and configure an automatic 301 redirect to HTTPS (Port 443)."
    },
    135: {
        "service": "MSRPC",
        "severity": "Medium",
        "title": "Microsoft RPC Endpoint Mapper Exposed",
        "description": "MSRPC can be queried to enumerate network services, user accounts, and system interfaces.",
        "remediation": "Block Port 135 at network perimeter firewalls and restrict access to authorized management subnets."
    },
    445: {
        "service": "SMB",
        "severity": "High",
        "title": "Server Message Block (SMB) Exposed",
        "description": "SMB file sharing services are frequent targets for lateral movement and wormable exploits.",
        "remediation": "Disable SMBv1, enforce SMB signing/encryption, and isolate Port 445 behind a firewall or VPN."
    },
    3389: {
        "service": "RDP",
        "severity": "High",
        "title": "Remote Desktop Protocol (RDP) Exposed",
        "description": "RDP endpoints are actively targeted for brute-force attacks and credential stuffing.",
        "remediation": "Place RDP behind a VPN, enable Network Level Authentication (NLA), and enforce Multi-Factor Authentication (MFA)."
    },
    53: {
        "service": "DNS",
        "severity": "Low",
        "title": "DNS Service Detected",
        "description": "Publicly accessible or misconfigured DNS servers can be leveraged in DNS amplification attacks.",
        "remediation": "Ensure DNS recursion is restricted to trusted internal clients only."
    }
}

# Offline CVE Cache for quick matching & offline lab demos
OFFLINE_CVE_CACHE = {
    "vsftpd 2.3.4": [
        {"id": "CVE-2011-2523", "cvss": 9.8, "summary": "vsftpd 2.3.4 contains a backdoor in the response routine."}
    ],
    "apache 2.4.49": [
        {"id": "CVE-2021-41773", "cvss": 7.5, "summary": "Path traversal flaw in Apache HTTP Server 2.4.49 allows file disclosure."}
    ],
    "openssh 7.2p2": [
        {"id": "CVE-2016-6210", "cvss": 5.3, "summary": "User enumeration vulnerability via timing attacks in OpenSSH."}
    ]
}


def search_online_cve(product, version):
    """Queries online CIRCL CVE API for known software versions."""
    if not product or product.lower() == "unknown":
        return []
    
    query = f"{product} {version}".strip() if version and version.lower() != "unknown" else product
    
    # Check offline demo cache first
    for key, cves in OFFLINE_CVE_CACHE.items():
        if key in query.lower():
            return cves

    url = f"https://cve.circl.lu/api/search/{requests.utils.quote(query)}"
    try:
        response = requests.get(url, timeout=4)
        if response.status_code == 200:
            data = response.json()
            results = data if isinstance(data, list) else data.get("results", [])
            extracted = []
            for item in results[:3]:
                if isinstance(item, dict):
                    extracted.append({
                        "id": item.get("id", "Unknown CVE"),
                        "cvss": item.get("cvss", 5.0),
                        "summary": item.get("summary", "No details available")
                    })
            return extracted
    except Exception:
        pass
    return []


def calculate_security_score(vulnerabilities):
    """
    Calculates security score (0-100) based on vulnerability findings.
    Starts at 100 and deducts points based on severity weights.
    """
    score = 100
    deductions = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Informational": 0
    }
    for vuln in vulnerabilities:
        score -= deductions.get(vuln.get("severity", "Low"), 3)
    
    score = max(0, score)
    
    if score >= 90:
        grade = "A (Secure)"
    elif score >= 75:
        grade = "B (Good)"
    elif score >= 50:
        grade = "C (Fair)"
    elif score >= 30:
        grade = "D (Poor)"
    else:
        grade = "F (Critical Risk)"
        
    return score, grade


def analyze_devices(devices_data):
    """
    Core function that inspects all scanned devices, ports, and services.
    Returns structured vulnerability assessments and security posture metrics.
    """
    assessment_results = []
    total_findings = 0

    for host in devices_data:
        ip = host.get("ip")
        mac = host.get("mac", "Unknown")
        host_findings = []

        for port_info in host.get("ports", []):
            port = port_info.get("port")
            service = port_info.get("service", "unknown")
            product = port_info.get("product", "Unknown")
            version = port_info.get("version", "Unknown")

            # 1. Evaluate Port & Policy Risk
            if port in PORT_POLICY_RULES:
                rule = PORT_POLICY_RULES[port]
                host_findings.append({
                    "port": port,
                    "service": service,
                    "type": "Policy/Service Exposure",
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "description": rule["description"],
                    "remediation": rule["remediation"]
                })

            # 2. Evaluate Software Version CVEs
            if product != "Unknown" or version != "Unknown":
                cves = search_online_cve(product, version)
                for cve in cves:
                    host_findings.append({
                        "port": port,
                        "service": service,
                        "type": "Software Vulnerability (CVE)",
                        "severity": "Critical" if cve.get("cvss", 0) >= 9.0 else "High" if cve.get("cvss", 0) >= 7.0 else "Medium",
                        "title": f"{cve['id']} in {product} {version}".strip(),
                        "description": cve.get("summary"),
                        "remediation": f"Upgrade {product} to the latest patched version."
                    })

        host_score, host_grade = calculate_security_score(host_findings)
        total_findings += len(host_findings)

        assessment_results.append({
            "ip": ip,
            "mac": mac,
            "security_score": host_score,
            "security_grade": host_grade,
            "findings_count": len(host_findings),
            "findings": host_findings
        })

    return assessment_results


def print_assessment_report(assessment_results):
    """Prints a clean CLI executive summary."""
    print("=" * 60)
    print("VULNERABILITY & RISK ASSESSMENT REPORT")
    print("=" * 60)

    for host in assessment_results:
        print(f"\n[Host] {host['ip']} ({host['mac']})")
        print(f"  Security Score: {host['security_score']}/100 [{host['security_grade']}]")
        print(f"  Vulnerabilities Found: {host['findings_count']}")

        if not host["findings"]:
            print("  [✓] No critical service risks identified.")
            continue

        for finding in host["findings"]:
            badge = f"[{finding['severity'].upper()}]"
            print(f"  - {badge} Port {finding['port']} ({finding['service']}): {finding['title']}")
            print(f"      Remediation: {finding['remediation']}")
    print("\n" + "=" * 60)


def main():
    # Test using the exact JSON output from Step 1
    sample_scan_data = [
        {
            "ip": "10.0.2.2",
            "mac": "52:55:0A:00:02:02",
            "ports": [
                {"port": 135, "service": "msrpc", "product": "Microsoft Windows RPC", "version": "Unknown"},
                {"port": 445, "service": "microsoft-ds", "product": "Unknown", "version": "Unknown"}
            ]
        },
        {
            "ip": "10.0.2.3",
            "mac": "52:55:0A:00:02:03",
            "ports": [
                {"port": 53, "service": "domain", "product": "Unknown", "version": "Unknown"}
            ]
        }
    ]
    results = analyze_devices(sample_scan_data)
    print_assessment_report(results)


if __name__ == "__main__":
    main()
