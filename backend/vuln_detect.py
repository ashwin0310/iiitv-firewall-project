import xml.etree.ElementTree as ET
import requests


XML_FILE = "port_scan_output.xml"


def extract_services():
    services = []

    try:
        tree = ET.parse(XML_FILE)
        root = tree.getroot()

        for host in root.findall("host"):
            address = host.find("address")

            if address is None:
                continue

            ip = address.get("addr")

            for port in host.findall("./ports/port"):
                state = port.find("state")
                service = port.find("service")

                if state is None or state.get("state") != "open":
                    continue

                if service is None:
                    continue

                service_name = service.get("name", "unknown")
                product = service.get("product", "")
                version = service.get("version", "")

                services.append({
                    "host": ip,
                    "port": port.get("portid"),
                    "service": service_name,
                    "product": product,
                    "version": version
                })

    except ET.ParseError as error:
        print(f"XML parsing error: {error}")
    except FileNotFoundError:
        print(f"File not found: {XML_FILE}")

    return services


def search_cves(service):
    product = service["product"]
    version = service["version"]
    service_name = service["service"]

    if product:
        search_text = product
        if version:
            search_text += f" {version}"
    else:
        search_text = service_name

    url = "https://cve.circl.lu/api/search/" + requests.utils.quote(search_text)

    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return []

        data = response.json()

        if isinstance(data, list):
            return data[:5]

        if isinstance(data, dict):
            return data.get("results", [])[:5]

    except requests.RequestException as error:
        print(f"API request failed: {error}")
    except ValueError:
        print("API returned invalid JSON.")

    return []


def main():
    print("VULNERABILITY DETECTION")
    print("-----------------------")

    services = extract_services()

    if not services:
        print("No open services found in the XML file.")
        return

    for service in services:
        print()
        print(f"Host: {service['host']}")
        print(f"Port: {service['port']}")
        print(f"Service: {service['service']}")
        print(f"Product: {service['product'] or 'Unknown'}")
        print(f"Version: {service['version'] or 'Unknown'}")

        cves = search_cves(service)

        if not cves:
            print("No potential CVE matches found.")
            continue

        print("Potential CVE matches:")

        for cve in cves:
            if isinstance(cve, dict):
                cve_id = cve.get("id", "Unknown CVE")
                summary = cve.get("summary", "No description available")
                print(f"- {cve_id}: {summary}")
            else:
                print(f"- {cve}")

        print()
        print("Note: These are potential matches, not confirmed vulnerabilities.")


if __name__ == "__main__":
    main()
