#!/usr/bin/env python3
"""Main entry point for the syslog server web application."""

import os
import socket
import sys

from handler import start_syslog_server
from webapp import app, socketio, _broadcast_performance_metrics
from database import DB_PATH, LOG_RETENTION_DAYS

# Flag to ensure the metrics broadcaster starts only once
_metrics_task_started = False

def create_app():
    """Initialize the Flask application and background tasks."""

    global _metrics_task_started
    if not _metrics_task_started:
        socketio.start_background_task(_broadcast_performance_metrics)
        _metrics_task_started = True

    return app


if __name__ == '__main__':
    print("Firewall Syslog Server - Fixed Database Locking Issues")
    print("=" * 60)

    # Ensure database directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    # Check if running as administrator on Windows
    is_admin = False
    try:
        if os.name == 'nt':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        pass

    # Determine port based on privileges
    syslog_port = 514 if is_admin else 5514

    if not is_admin and os.name == 'nt':
        print("⚠️  Not running as Administrator")
        print(f"Using non-privileged port {syslog_port} instead of 514")
        print("To use standard port 514, run as Administrator")
        print()

    try:
        # Start syslog server
        syslog_server = start_syslog_server(port=syslog_port)

        # Get local IP address
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "localhost"

        print("Server Configuration:")
        print(f"- Syslog UDP Port: {syslog_port}")
        print(f"- Web Dashboard: http://{local_ip}:5000")
        print(f"- Database: {DB_PATH}")
        print(f"- Log Retention: {LOG_RETENTION_DAYS} days")
        print()
        print("Firewall Configuration:")
        print("Configure your firewalls to send syslog messages to:")
        print(f"  Server IP: {local_ip}")
        print(f"  Port: {syslog_port}/UDP")
        print()

        # Prepare and start Flask web server
        app = create_app()
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        if 'syslog_server' in locals():
            syslog_server.shutdown()
        print("Server stopped.")
