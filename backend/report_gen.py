import os
import json
from datetime import datetime
from database import get_latest_scan_from_db


def generate_html_report(scan_data=None, output_filename="security_audit_report.html"):
    """
    Generates a formal, printable security audit report from the scan data.
    If scan_data is not provided, it pulls the latest scan from SQLite or JSON.
    """
    if scan_data is None:
        scan_data = get_latest_scan_from_db()
      
    # Fallback to existing JSON snapshot if SQLite is still empty
    if not scan_data and os.path.exists("network_security_output.json"):
        try:
            with open("network_security_output.json", "r") as f:
                scan_data = json.load(f)
        except Exception:
            pass
    if not scan_data:
        print("[!] Error: No scan data found to generate a report.")
        return None
    net_info = scan_data.get("network_info", {})
    timestamp = scan_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    assessment_results = scan_data.get("assessment_results", [])
    discovered_hosts = scan_data.get("discovered_hosts", [])

    # Calculate aggregate metrics
    total_findings = 0
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    scores = []

    for host in assessment_results:
        scores.append(host.get("security_score", 100))
        for finding in host.get("findings", []):
            total_findings += 1
            sev = finding.get("severity", "Low")
            if sev in severity_counts:
                severity_counts[sev] += 1

    avg_score = round(sum(scores) / len(scores)) if scores else 100
    if avg_score >= 85:
        overall_grade = "A (Secure)"
        grade_color = "#10b981"
    elif avg_score >= 70:
        overall_grade = "B (Good)"
        grade_color = "#3b82f6"
    elif avg_score >= 50:
        overall_grade = "C (Fair)"
        grade_color = "#f59e0b"
    else:
        overall_grade = "D/F (High Risk)"
        grade_color = "#ef4444"

    # Build Host Findings HTML Rows
    findings_html = ""
    for host in assessment_results:
        findings_html += f"""
        <div class="host-section">
            <div class="host-header">
                <div>
                    <span class="host-ip">{host.get('ip')}</span>
                    <span class="host-mac">({host.get('mac', 'Unknown MAC')})</span>
                </div>
                <div class="host-score-badge">Score: {host.get('security_score')}/100 [{host.get('security_grade')}]</div>
            </div>
        """
        if host.get("findings"):
            findings_html += '<table class="vuln-table"><thead><tr><th>Severity</th><th>Port/Service</th><th>Vulnerability / Policy Finding</th><th>Remediation Advice</th></tr></thead><tbody>'
            for f in host.get("findings", []):
                sev = f.get("severity", "Low")
                sev_badge_class = f"badge-{sev.lower()}"
                findings_html += f"""
                <tr>
                    <td><span class="badge {sev_badge_class}">{sev}</span></td>
                    <td><b>{f.get('port')}</b> / {f.get('service')}</td>
                    <td><b>{f.get('title')}</b><br><small style="color:#64748b;">{f.get('description')}</small></td>
                    <td style="color:#059669;"><b>{f.get('remediation')}</b></td>
                </tr>
                """
            findings_html += '</tbody></table>'
        else:
            findings_html += '<p style="color: #059669; margin-top: 8px;">✓ No high-risk exposures or policy violations detected.</p>'
        findings_html += "</div>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Network Security Assessment Report - IIIT Vadodara</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #1e293b;
            background-color: #f8fafc;
            margin: 0;
            padding: 30px;
        }}
        .report-container {{
            max-width: 900px;
            margin: 0 auto;
            background: #ffffff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }}
        .header {{
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 20px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}
        .title-area h1 {{ margin: 0; font-size: 24px; color: #0f172a; }}
        .title-area p {{ margin: 4px 0 0 0; color: #64748b; font-size: 13px; }}
        .meta-box {{ text-align: right; font-size: 12px; color: #64748b; }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}
        .card {{
            background: #f1f5f9;
            padding: 16px;
            border-radius: 8px;
            text-align: center;
        }}
        .card-num {{ font-size: 26px; font-weight: bold; margin-top: 4px; }}
        .card-label {{ font-size: 11px; text-transform: uppercase; color: #64748b; letter-spacing: 0.5px; }}
        .host-section {{
            margin-bottom: 25px;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            background: #ffffff;
        }}
        .host-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #f1f5f9;
            padding-bottom: 10px;
        }}
        .host-ip {{ font-size: 16px; font-weight: bold; font-family: monospace; color: #1e293b; }}
        .host-mac {{ font-size: 12px; color: #64748b; font-family: monospace; }}
        .host-score-badge {{
            font-size: 12px;
            font-weight: bold;
            background: #e2e8f0;
            padding: 4px 10px;
            border-radius: 6px;
        }}
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 12px;
        }}
        .vuln-table th, .vuln-table td {{
            text-align: left;
            padding: 10px 8px;
            border-bottom: 1px solid #f1f5f9;
        }}
        .vuln-table th {{ background: #f8fafc; color: #475569; font-weight: 600; }}
        .badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 10px;
            text-transform: uppercase;
            color: #fff;
            display: inline-block;
        }}
        .badge-critical {{ background: #dc2626; }}
        .badge-high {{ background: #ea580c; }}
        .badge-medium {{ background: #d97706; }}
        .badge-low {{ background: #2563eb; }}
        .footer {{
            margin-top: 40px;
            border-top: 1px solid #e2e8f0;
            padding-top: 15px;
            font-size: 11px;
            color: #94a3b8;
            text-align: center;
        }}
        @media print {{
            body {{ background: #ffffff; padding: 0; }}
            .report-container {{ box-shadow: none; padding: 10px; max-width: 100%; }}
            .no-print {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="no-print" style="text-align: right; margin-bottom: 15px;">
            <button onclick="window.print()" style="padding: 8px 16px; background: #2563eb; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;">
                Print / Save as PDF
            </button>
        </div>

        <div class="header">
            <div class="title-area">
                <h1>Network Vulnerability Assessment Report</h1>
                <p>IIIT Vadodara • M.Tech in Cyber Security (EMCY103: Network Security and Firewall)</p>
            </div>
            <div class="meta-box">
                <div><b>Date:</b> {timestamp}</div>
                <div><b>Target Subnet:</b> {net_info.get('subnet', 'N/A')}</div>
                <div><b>Gateway:</b> {net_info.get('gateway', 'N/A')}</div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="card">
                <div class="card-label">Security Posture Score</div>
                <div class="card-num" style="color: {grade_color};">{avg_score}/100</div>
                <div style="font-size: 11px; color: #64748b; margin-top: 2px;">Grade: {overall_grade}</div>
            </div>
            <div class="card">
                <div class="card-label">Reachable Devices</div>
                <div class="card-num" style="color: #0284c7;">{len(discovered_hosts)}</div>
                <div style="font-size: 11px; color: #64748b; margin-top: 2px;">Live Hosts Scanned</div>
            </div>
            <div class="card">
                <div class="card-label">Total Vulnerabilities</div>
                <div class="card-num" style="color: #d97706;">{total_findings}</div>
                <div style="font-size: 11px; color: #64748b; margin-top: 2px;">Policy & CVE Risks</div>
            </div>
            <div class="card">
                <div class="card-label">High / Critical Risks</div>
                <div class="card-num" style="color: #dc2626;">{severity_counts['Critical'] + severity_counts['High']}</div>
                <div style="font-size: 11px; color: #64748b; margin-top: 2px;">Action Required</div>
            </div>
        </div>

        <h3 style="font-size: 16px; margin-bottom: 12px;">Detailed Device Findings & Remediation</h3>
        {findings_html}

        <div class="footer">
            Submitted by: Ashwin Behere (202606511004) & Amishi Sinvar (202606511021) • Guided By: Tejas Kalal Sir • IIIT Vadodara
        </div>
    </div>
</body>
</html>
"""
    with open(output_filename, "w") as f:
        f.write(html_content)
    
    print(f"[✓] Security Assessment Report generated: {output_filename}")
    return output_filename


if __name__ == "__main__":
    generate_html_report()
