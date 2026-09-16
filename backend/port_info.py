import subprocess
import json

def run_nmap_scan(targets):
    """
    Run Nmap scan on the given targets.
    Scans top 1000 TCP ports and detects services.
    """
    command = [
        "nmap",
        "-sV",          # Service/version detection
        "-T4",          # Faster execution
        "-Pn",          # Treat hosts as online (skip ping)
        "--top-ports", "1000",
        "-oX", "-"      # Output in XML to stdout
    ] + targets

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout


def main():
    # Example: replace with discovered hosts from network_info.py
    targets = ["10.0.2.2", "10.0.2.3", "10.0.2.15"]

    print("PORT & SERVICE DETECTION")
    print("------------------------")
    print(f"Scanning {len(targets)} hosts...")

    xml_output = run_nmap_scan(targets)

    # For now, just print raw XML output
    # Later we’ll parse and format results
    print(xml_output)


if __name__ == "__main__":
    main()
