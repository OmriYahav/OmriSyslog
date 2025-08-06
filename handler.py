import re
import socketserver
import threading
from datetime import datetime, timezone
from typing import Dict

from database import log_queue, logger

socketio = None


def set_socketio(sio):
    """Attach a Socket.IO instance for real-time log streaming."""
    global socketio
    socketio = sio


class SyslogHandler(socketserver.BaseRequestHandler):
    """Handle incoming syslog messages."""

    def handle(self):
        try:
            data = self.request[0].decode('utf-8', errors='replace').strip()
            client_ip = self.client_address[0]

            # Parse syslog message
            log_entry = self.parse_syslog(data, client_ip)

            # Avoid printing every log to the console; keep for debugging only
            logger.debug(
                f"{log_entry['timestamp']} {log_entry['source_ip']} {log_entry['message']}"
            )

            # Add to queue for batch processing instead of immediate DB write
            log_queue.put(log_entry)

            # Emit to web clients via WebSocket (non-blocking)
            if socketio:
                try:
                    socketio.emit('new_log', log_entry, namespace='/logs')
                except Exception as ws_error:
                    logger.warning(f"WebSocket emit error: {ws_error}")
        except Exception as e:
            logger.error(f"Error handling syslog message: {e}")

    @staticmethod
    def parse_syslog(message: str, source_ip: str) -> Dict:
        """Parse syslog message into structured format.

        This method does not rely on instance state and is therefore a
        ``@staticmethod``. Making it static simplifies testing and allows the
        parser to be used independently of an active ``SyslogHandler``
        instance.
        """

        timestamp = datetime.now(timezone.utc)

        # Basic syslog format parsing
        # Format: <priority>timestamp hostname tag: message
        priority_match = re.match(r'^<(\d+)>', message)
        priority = int(priority_match.group(1)) if priority_match else 0

        # Extract facility and severity
        facility = priority >> 3
        severity = priority & 0x07

        # Remove priority from message
        if priority_match:
            message = message[priority_match.end():]

        # Try to extract timestamp if present
        timestamp_patterns = [
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # MMM dd HH:mm:ss
            r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',   # ISO format
        ]

        extracted_timestamp = None
        for pattern in timestamp_patterns:
            match = re.match(pattern, message.strip())
            if match:
                try:
                    if 'T' in match.group(1):
                        extracted_timestamp = datetime.fromisoformat(match.group(1))
                    else:
                        # Add current year for syslog format
                        time_str = f"{datetime.now().year} {match.group(1)}"
                        extracted_timestamp = datetime.strptime(time_str, "%Y %b %d %H:%M:%S")
                    message = message[match.end():].strip()
                    break
                except Exception:
                    pass

        if extracted_timestamp:
            timestamp = extracted_timestamp.replace(tzinfo=timezone.utc)

        # Parse FortiGate/firewall structured log format
        # Look for devname="..." pattern
        devname_match = re.search(r'devname="([^"]+)"', message)
        devname = devname_match.group(1) if devname_match else None

        # Extract optional client-specific name
        client_name = None
        for pattern in [
            r'client_name="([^"]+)"',
            r'clientname="([^"]+)"',
            r'client="([^"]+)"',
        ]:
            match = re.search(pattern, message)
            if match:
                client_name = match.group(1)
                break

        if not client_name and devname:
            client_name = devname

        # Extract logid for categorization
        logid_match = re.search(r'logid="([^"]+)"', message)
        logid = logid_match.group(1) if logid_match else None

        # Extract type and subtype
        type_match = re.search(r'type="([^"]+)"', message)
        log_type = type_match.group(1) if type_match else "unknown"

        subtype_match = re.search(r'subtype="([^"]+)"', message)
        log_subtype = subtype_match.group(1) if subtype_match else "unknown"

        # Extract level for severity mapping
        level_match = re.search(r'level="([^"]+)"', message)
        level = level_match.group(1) if level_match else None

        # Map FortiGate level to syslog severity if available
        if level:
            level_severity_map = {
                'emergency': 0,
                'alert': 1,
                'critical': 2,
                'error': 3,
                'warning': 4,
                'notice': 5,
                'information': 6,
                'informational': 6,
                'info': 6,
                'debug': 7,
            }
            mapped_severity = level_severity_map.get(level.lower())
            if mapped_severity is not None:
                severity = mapped_severity

        # Use devname as hostname if available, fallback to parsing traditional format
        if devname:
            hostname = devname
            program = f"{log_type}/{log_subtype}" if log_type != "unknown" else "firewall"
        else:
            # Fallback to traditional parsing
            parts = message.split(':', 1)
            hostname_program = parts[0].strip() if parts else "unknown"
            hostname_parts = hostname_program.split()
            hostname = hostname_parts[0] if hostname_parts else source_ip
            program = hostname_parts[1] if len(hostname_parts) > 1 else "firewall"

        # Clean message for better readability
        log_message = message

        return {
            'timestamp': timestamp.isoformat(),
            'source_ip': source_ip,
            'hostname': hostname,
            'client_name': client_name,
            'program': program,
            'facility': facility,
            'severity': severity,
            'message': log_message,
            'raw_message': message,
            'logid': logid,
            'log_type': log_type,
            'log_subtype': log_subtype,
            'level': level
        }


def start_syslog_server(host='0.0.0.0', port=5514):
    """Start the syslog UDP server."""
    logger.info(f"Starting syslog server on {host}:{port}")

    class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
        daemon_threads = True
        allow_reuse_address = True

        def __init__(self, server_address, RequestHandlerClass):
            # Windows-specific socket options
            super().__init__(server_address, RequestHandlerClass)
            if hasattr(self.socket, 'setsockopt'):
                import socket
                try:
                    # Enable address reuse
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except Exception:
                    pass

    try:
        server = ThreadedUDPServer((host, port), SyslogHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        logger.info(f"\u2713 Syslog server started successfully on {host}:{port}")
        return server
    except PermissionError:
        logger.error(f"\u2717 Permission denied for port {port}")
        print("Solutions:")
        print("1. Run as Administrator (for port 514)")
        print("2. Use non-privileged port (current: 5514)")
        print("3. Configure firewall to allow the application")
        # Try alternative ports
        for alt_port in [5514, 1514, 10514]:
            try:
                logger.info(f"Trying alternative port {alt_port}...")
                server = ThreadedUDPServer((host, alt_port), SyslogHandler)
                server_thread = threading.Thread(target=server.serve_forever, daemon=True)
                server_thread.start()
                logger.info(f"\u2713 Syslog server started on alternative port {host}:{alt_port}")
                return server
            except Exception:
                continue
        raise Exception("Could not bind to any available port")
