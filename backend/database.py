import sqlite3
import json
from datetime import datetime

DB_NAME = "scanner.db"


def init_db():
    """Initializes SQLite database tables for scans, hosts, vulnerabilities, and alerts."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # 1. Scans Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            subnet TEXT,
            gateway TEXT,
            interface TEXT,
            total_hosts INTEGER,
            elapsed_seconds REAL
        )
    """)

    # 2. Hosts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT NOT NULL,
            mac TEXT,
            security_score INTEGER,
            security_grade TEXT,
            findings_count INTEGER,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    """)

    # 3. Vulnerabilities & Findings Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            scan_id INTEGER,
            ip TEXT,
            port INTEGER,
            service TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            remediation TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts (id),
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    """)

    # 4. Security Alerts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            category TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_scan_to_db(audit_snapshot):
    """Saves a complete scan snapshot into SQLite."""
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    net_info = audit_snapshot.get("network_info", {})
    discovered_hosts = audit_snapshot.get("discovered_hosts", [])
    assessment_results = audit_snapshot.get("assessment_results", [])

    # Insert scan record
    cursor.execute("""
        INSERT INTO scans (timestamp, subnet, gateway, interface, total_hosts, elapsed_seconds)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        audit_snapshot.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        net_info.get("subnet"),
        net_info.get("gateway"),
        net_info.get("interface"),
        len(discovered_hosts),
        audit_snapshot.get("elapsed_seconds", 0.0)
    ))
    scan_id = cursor.lastrowid

    # Insert hosts and their findings
    for host in assessment_results:
        cursor.execute("""
            INSERT INTO hosts (scan_id, ip, mac, security_score, security_grade, findings_count)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            host.get("ip"),
            host.get("mac"),
            host.get("security_score"),
            host.get("security_grade"),
            host.get("findings_count", 0)
        ))
        host_id = cursor.lastrowid

        for finding in host.get("findings", []):
            cursor.execute("""
                INSERT INTO vulnerabilities (host_id, scan_id, ip, port, service, severity, title, description, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                host_id,
                scan_id,
                host.get("ip"),
                finding.get("port"),
                finding.get("service"),
                finding.get("severity"),
                finding.get("title"),
                finding.get("description"),
                finding.get("remediation")
            ))

    conn.commit()
    conn.close()
    return scan_id


def save_alert_to_db(alert):
    """Saves an individual real-time alert into SQLite."""
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (timestamp, level, category, message)
        VALUES (?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        alert.get("level", "INFO"),
        alert.get("category", "GENERAL"),
        alert.get("message", "")
    ))
    conn.commit()
    conn.close()


def get_latest_scan_from_db():
    """Fetches the latest scan record along with hosts and findings."""
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT id, timestamp, subnet, gateway, interface, total_hosts FROM scans ORDER BY id DESC LIMIT 1")
    scan_row = cursor.fetchone()
    if not scan_row:
        conn.close()
        return None

    scan_id, timestamp, subnet, gateway, interface, total_hosts = scan_row

    cursor.execute("SELECT id, ip, mac, security_score, security_grade, findings_count FROM hosts WHERE scan_id = ?", (scan_id,))
    host_rows = cursor.fetchall()

    assessment_results = []
    for h_id, ip, mac, score, grade, count in host_rows:
        cursor.execute("SELECT port, service, severity, title, description, remediation FROM vulnerabilities WHERE host_id = ?", (h_id,))
        vuln_rows = cursor.fetchall()
        findings = []
        for port, service, severity, title, desc, remed in vuln_rows:
            findings.append({
                "port": port,
                "service": service,
                "severity": severity,
                "title": title,
                "description": desc,
                "remediation": remed
            })
        
        assessment_results.append({
            "ip": ip,
            "mac": mac,
            "security_score": score,
            "security_grade": grade,
            "findings_count": count,
            "findings": findings
        })

    conn.close()
    return {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "network_info": {
            "subnet": subnet,
            "gateway": gateway,
            "interface": interface
        },
        "discovered_hosts": [h["ip"] for h in assessment_results],
        "assessment_results": assessment_results
    }


if __name__ == "__main__":
    init_db()
    print("[✓] SQLite database scanner.db initialized successfully.")
