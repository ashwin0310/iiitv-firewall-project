import os
import sys
import socket
import subprocess

from PySide6.QtCore import QUrl, QTimer
from PySide6.QtWidgets import QApplication, QMainWindow
from PySide6.QtWebEngineWidgets import QWebEngineView

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HOST = "127.0.0.1"
PORT = 8000
URL = f"http://{HOST}:{PORT}/"


def server_running():
    try:
        with socket.create_connection((HOST, PORT), timeout=1):
            return True
    except OSError:
        return False


class ScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.server_process = None
        self.attempts = 0

        self.setWindowTitle("Network Vulnerability Scanner")
        self.resize(1280, 800)

        self.webview = QWebEngineView()
        self.setCentralWidget(self.webview)

        self.start_backend()
        QTimer.singleShot(1000, self.load_dashboard)

    def start_backend(self):
        if server_running():
            return

        self.server_process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app:app",
                "--host",
                HOST,
                "--port",
                str(PORT)
            ],
            cwd=BASE_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    def load_dashboard(self):
        if server_running():
            self.webview.setUrl(QUrl(URL))
            return

        self.attempts += 1

        if self.attempts < 30:
            QTimer.singleShot(1000, self.load_dashboard)
        else:
            self.webview.setHtml(
                "<h2>Scanner backend could not start.</h2>"
                "<p>Check that uvicorn and project dependencies are installed.</p>"
            )

    def closeEvent(self, event):
        if self.server_process and self.server_process.poll() is None:
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
                self.server_process.wait()

        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = ScannerApp()
    window.show()

    sys.exit(app.exec())
