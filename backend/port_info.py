import subprocess
import xml.etree.ElementTree as ET
import json


def scan_ports(targets, top_ports=100):
    """
    Scans targets with optimized nmap flags.
    --open ensures nmap only performs version detection on confirmed open ports.
    -T4 accelerates execution.
    """
    if not targets:
        return []

    command = [
        "nmap",
        "--privileged",
        "-sS",
        "-sV",
        "--open",
        "-T4",
        "-Pn",
        f"--top-ports={top_ports}",
        "-oX",
        "-",
    ] + targets

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0 and not result.stdout:
        print(f"Error running nmap: {result.stderr}")
        return []

    # Parse XML output directly in-memory
    return parse_nmap_xml(result.stdout)


def parse_nmap_xml(xml_content):
    """Parses raw nmap XML string into structured host & port dictionaries."""
    devices = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        print(f"XML Parsing Error: {e}")
        return devices

    for host in root.findall("host"):
        # Check if host is up
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Extract IP address
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr")

        # Extract MAC address if present
        mac_elem = host.find("address[@addrtype='mac']")
        mac = mac_elem.get("addr") if mac_elem is not None else "Unknown"

        host_entry = {
            "ip": ip,
            "mac": mac,
            "ports": []
        }

        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_id = int(port.get("portid"))
                protocol = port.get("protocol")

                service_elem = port.find("service")
                service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.get("product", "Unknown") if service_elem is not None else "Unknown"
                version = service_elem.get("version", "Unknown") if service_elem is not None else "Unknown"

                # Extract CPE if available
                cpe_elem = service_elem.find("cpe") if service_elem is not None else None
                cpe = cpe_elem.text if cpe_elem is not None else ""

                host_entry["ports"].append({
                    "port": port_id,
                    "protocol": protocol,
                    "state": "open",
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "cpe": cpe
                })

        devices.append(host_entry)

    return devices


def main():
    # Test scan with local gateway and DNS
    sample_targets = ["10.0.2.2", "10.0.2.3"]
    print(f"Scanning targets: {sample_targets} ...")
    results = scan_ports(sample_targets, top_ports=100)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
