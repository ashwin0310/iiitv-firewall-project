import concurrent.futures
import ipaddress
import re
import socket
import subprocess


def get_local_ip():
    """
    Detect the IPv4 address used for external communication.
    No application data is sent to the internet.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]

    except OSError:
        return None

    finally:
        sock.close()


def get_interface_and_prefix(ip_address):
    """
    Find the network interface and subnet prefix
    associated with the detected IPv4 address.
    """
    command = ["ip", "-4", "addr", "show"]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    interface = None
    prefix_length = None
    current_interface = None

    for line in result.stdout.splitlines():
        # Example:
        # 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
        interface_match = re.match(r"\d+:\s+([^:]+):", line)

        if interface_match:
            current_interface = interface_match.group(1)

        # Example:
        # inet 10.0.2.15/24 ...
        address_match = re.search(
            rf"\binet\s+{re.escape(ip_address)}/(\d+)",
            line
        )

        if address_match:
            interface = current_interface
            prefix_length = int(address_match.group(1))
            break

    return interface, prefix_length


def get_default_gateway():
    """
    Read the default gateway from the Linux routing table.
    """
    result = subprocess.run(
        ["ip", "route"],
        capture_output=True,
        text=True,
        check=True
    )

    for line in result.stdout.splitlines():
        parts = line.split()

        if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
            return parts[2]

    return None


def ping_host(ip_address):
    """
    Send one ICMP ping to a host.

    Returns the IP address if the host responds.
    Returns None if it does not respond.
    """
    result = subprocess.run(
        [
            "ping",
            "-c", "1",
            "-W", "1",
            str(ip_address)
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if result.returncode == 0:
        return str(ip_address)

    return None


def discover_hosts(network):
    """
    Check the usable IPv4 addresses in the detected subnet.

    A thread pool is used so hosts are checked in parallel
    instead of waiting one second for each address.
    """
    discovered_hosts = []

    addresses = list(network.hosts())

    print("\nDEVICE DISCOVERY")
    print("----------------")
    print(f"Checking {len(addresses)} possible host addresses...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        results = executor.map(ping_host, addresses)

        for result in results:
            if result is not None:
                discovered_hosts.append(result)

    return discovered_hosts


def main():
    hostname = socket.gethostname()
    ip_address = get_local_ip()

    if ip_address is None:
        print("Unable to detect the local IPv4 address.")
        return

    interface, prefix_length = get_interface_and_prefix(ip_address)

    if interface is None or prefix_length is None:
        print("Unable to detect the network interface or subnet.")
        return

    network = ipaddress.ip_network(
        f"{ip_address}/{prefix_length}",
        strict=False
    )

    gateway = get_default_gateway()

    print("NETWORK INFORMATION")
    print("-------------------")
    print(f"Hostname: {hostname}")
    print(f"Interface: {interface}")
    print(f"IP address: {ip_address}")
    print(f"Subnet: {network}")
    print(f"Gateway: {gateway if gateway else 'Not found'}")

    discovered_hosts = discover_hosts(network)

    print("\nREACHABLE HOSTS")
    print("----------------")

    if discovered_hosts:
        for host in discovered_hosts:
            print(host)
    else:
        print("No hosts responded to the ping probe.")

    print(f"\nTotal reachable hosts: {len(discovered_hosts)}")


if __name__ == "__main__":
    main()
