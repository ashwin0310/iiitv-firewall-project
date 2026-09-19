from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
import os
import json

from main import run_full_security_assessment
from monitor import load_previous_state, detect_network_changes, HISTORY_FILE, STATE_FILE
from database import get_latest_scan_from_db, save_scan_to_db
from report_gen import generate_html_report

app = FastAPI(title="Network Vulnerability Scanner & Real-Time Security Monitor")
templates = Jinja2Templates(directory="templates")

IS_SCANNING = False


@app.get("/", response_class=HTMLResponse)
def get_dashboard(request: Request):
    """Renders the main security monitoring dashboard."""
    # Pull latest from SQLite, fallback to JSON
    state = get_latest_scan_from_db() or load_previous_state() or {
        "timestamp": "Never",
        "network_info": {"subnet": "N/A", "gateway": "N/A", "ip_address": "N/A", "interface": "N/A"},
        "discovered_hosts": [],
        "assessment_results": []
    }
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"state": state}
    )


@app.get("/report", response_class=HTMLResponse)
def view_report():
    """Serves the generated HTML security assessment report."""
    report_file = "security_audit_report.html"
    if not os.path.exists(report_file):
        generate_html_report()
    if os.path.exists(report_file):
        with open(report_file, "r") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>No report generated yet. Run a scan first.</h1>")


@app.get("/report/download")
def download_report():
    """Downloads the HTML security assessment report file."""
    report_file = "security_audit_report.html"
    if not os.path.exists(report_file):
        generate_html_report()
    return FileResponse(report_file, media_type="text/html", filename="IIITV_Security_Audit_Report.html")


@app.get("/api/state")
def get_current_state():
    state = get_latest_scan_from_db() or load_previous_state()
    return state if state else {"error": "No scan data available yet."}


def background_scan_task():
    global IS_SCANNING
    IS_SCANNING = True
    try:
        current_state = run_full_security_assessment(top_ports=100, save_output=True)
        if current_state:
            prev_state = load_previous_state()
            alerts = detect_network_changes(prev_state, current_state)
            current_state["latest_alerts"] = alerts
            with open(STATE_FILE, "w") as f:
                json.dump(current_state, f, indent=2)
    finally:
        IS_SCANNING = False


@app.post("/api/scan/trigger")
def trigger_scan(background_tasks: BackgroundTasks):
    global IS_SCANNING
    if IS_SCANNING:
        return JSONResponse(status_code=409, content={"message": "A scan is already in progress."})
    background_tasks.add_task(background_scan_task)
    return {"status": "Scan initiated in background."}


@app.get("/api/scan/status")
def get_scan_status():
    return {"is_scanning": IS_SCANNING}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

