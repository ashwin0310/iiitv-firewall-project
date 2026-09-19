import concurrent.futures
import ipaddress
import re
import socket
import subprocess


def get_local_ip():
    """Detect the IPv4 address used for external communication."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def get_interface_and_prefix(ip_address):
    """Find network interface and subnet prefix associated with the detected IPv4."""
    command = ["ip", "-4", "addr", "show"]
    result = subprocess.run(command, capture_output=True, text=True, check=True)

    interface = None
    prefix_length = None
    current_interface = None

    for line in result.stdout.splitlines():
        interface_match = re.match(r"\d+:\s+([^:]+):", line)
        if interface_match:
            current_interface = interface_match.group(1)

        address_match = re.search(rf"\binet\s+{re.escape(ip_address)}/(\d+)", line)
        if address_match:
            interface = current_interface
            prefix_length = int(address_match.group(1))
            break

    return interface, prefix_length


def get_default_gateway():
    """Read the default gateway from the Linux routing table."""
    result = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
            return parts[2]
    return None


def ping_host(ip_address):
    """Send one ICMP ping to a host. Returns IP if reachable, else None."""
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", str(ip_address)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return str(ip_address) if result.returncode == 0 else None


def discover_hosts(network, max_workers=64):
    """Parallel ping sweep across the subnet."""
    discovered_hosts = []
    addresses = list(network.hosts())

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(ping_host, addresses)
        for result in results:
            if result:
                discovered_hosts.append(result)

    return discovered_hosts


def get_network_details():
    """Modular function to retrieve all network details and reachable hosts."""
    hostname = socket.gethostname()
    ip_address = get_local_ip()
    if not ip_address:
        return None, []

    interface, prefix_length = get_interface_and_prefix(ip_address)
    if not interface or not prefix_length:
        return None, []

    network = ipaddress.ip_network(f"{ip_address}/{prefix_length}", strict=False)
    gateway = get_default_gateway()

    net_info = {
        "hostname": hostname,
        "interface": interface,
        "ip_address": ip_address,
        "subnet": str(network),
        "gateway": gateway or "Not found",
    }

    hosts = discover_hosts(network)
    return net_info, hosts


def main():
    net_info, discovered_hosts = get_network_details()
    if not net_info:
        print("Failed to detect network configuration.")
        return

    print("NETWORK INFORMATION")
    print("-------------------")
    print(f"Hostname:   {net_info['hostname']}")
    print(f"Interface:  {net_info['interface']}")
    print(f"IP address: {net_info['ip_address']}")
    print(f"Subnet:     {net_info['subnet']}")
    print(f"Gateway:    {net_info['gateway']}")

    print("\nDEVICE DISCOVERY")
    print("----------------")
    print(f"Total reachable hosts: {len(discovered_hosts)}")
    for host in discovered_hosts:
        print(f"  [+] {host}")


if __name__ == "__main__":
    main()
