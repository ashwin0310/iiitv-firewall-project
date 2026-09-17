import subprocess
import sys


def run_module(module_name):
    print()
    print("=" * 50)
    print(f"Running: {module_name}")
    print("=" * 50)

    result = subprocess.run(
        [sys.executable, module_name],
        text=True
    )

    if result.returncode != 0:
        print(f"{module_name} failed.")
        return False

    print(f"{module_name} completed successfully.")
    return True


def main():
    print("NETWORK VULNERABILITY SCANNER")
    print("============================")

    modules = [
        "network_info.py",
        "port_info.py",
        "vuln_detect.py"
    ]

    for module in modules:
        success = run_module(module)

        if not success:
            print("Scanning stopped because a module failed.")
            return

    print()
    print("=" * 50)
    print("FULL SCAN COMPLETED")
    print("=" * 50)
    print("Nmap results are saved in port_scan_output.xml")


if __name__ == "__main__":
    main()
