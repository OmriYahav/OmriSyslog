import json
import os
import sqlite3
import tempfile
import time
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_file
from flask_socketio import SocketIO

from database import db_manager, db_pool, logger
from handler import set_socketio

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    psutil = None

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
set_socketio(socketio)

# Severity level mapping
SEVERITY_LEVELS = {
    0: 'Emergency',
    1: 'Alert',
    2: 'Critical',
    3: 'Error',
    4: 'Warning',
    5: 'Notice',
    6: 'Info',
    7: 'Debug'
}


# Performance metrics tracking
_last_cpu = None
_last_net = None


def _read_cpu_usage():
    """Return CPU utilization percentage."""
    global _last_cpu
    try:
        if psutil:
            return psutil.cpu_percent(interval=None)
        with open("/proc/stat", "r") as f:
            parts = f.readline().split()
        values = list(map(int, parts[1:]))
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values)
        if _last_cpu is None:
            _last_cpu = (total, idle)
            return 0.0
        total_diff = total - _last_cpu[0]
        idle_diff = idle - _last_cpu[1]
        _last_cpu = (total, idle)
        return (1 - idle_diff / total_diff) * 100 if total_diff else 0.0
    except Exception as e:
        logger.error(f"Error reading CPU usage: {e}")
        return 0.0


def _read_memory_usage():
    """Return total, used and percent memory usage."""
    try:
        if psutil:
            mem = psutil.virtual_memory()
            return mem.total, mem.used, mem.percent
        meminfo = {}
        with open("/proc/meminfo") as f:
            for line in f:
                key, value = line.split(":", 1)
                meminfo[key] = int(value.strip().split()[0]) * 1024
        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        used = total - available
        percent = (used / total * 100) if total else 0.0
        return total, used, percent
    except Exception as e:
        logger.error(f"Error reading memory usage: {e}")
        return 0, 0, 0.0


def _read_network_usage():
    """Return network receive/send rate in bytes per second."""
    global _last_net
    try:
        if psutil:
            counters = psutil.net_io_counters()
            recv = counters.bytes_recv
            sent = counters.bytes_sent
        else:
            with open("/proc/net/dev") as f:
                lines = f.readlines()[2:]
            recv = sent = 0
            for line in lines:
                if ":" not in line:
                    continue
                iface, data = line.split(":", 1)
                iface = iface.strip()
                if iface == "lo":
                    continue
                fields = data.split()
                recv += int(fields[0])
                sent += int(fields[8])
        now = time.time()
        if _last_net is None:
            _last_net = (now, recv, sent)
            return 0.0, 0.0
        prev_time, prev_recv, prev_sent = _last_net
        duration = max(now - prev_time, 1e-6)
        recv_rate = (recv - prev_recv) / duration
        send_rate = (sent - prev_sent) / duration
        _last_net = (now, recv, sent)
        return recv_rate, send_rate
    except Exception as e:
        logger.error(f"Error reading network usage: {e}")
        return 0.0, 0.0


def _broadcast_performance_metrics():
    """Continuously broadcast performance metrics via WebSocket."""
    while True:
        cpu = _read_cpu_usage()
        mem_total, mem_used, mem_percent = _read_memory_usage()
        net_recv, net_send = _read_network_usage()
        socketio.emit(
            "system_stats",
            {
                "cpu_percent": cpu,
                "memory_total": mem_total,
                "memory_used": mem_used,
                "memory_percent": mem_percent,
                "net_recv_rate": net_recv,
                "net_send_rate": net_send,
            },
            namespace="/logs",
        )
        socketio.sleep(5)


# Start background task to push system metrics to clients
socketio.start_background_task(_broadcast_performance_metrics)


@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/logs')
def api_logs():
    """API endpoint for log search"""
    query = request.args.get('query', '')
    source_ip = request.args.get('source_ip', '')
    hostname = request.args.get('hostname', '')
    severity = request.args.get('severity')
    start_time = request.args.get('start_time', '')
    end_time = request.args.get('end_time', '')
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))

    severity = int(severity) if severity and severity.isdigit() else None

    logs = db_manager.search_logs(
        query=query,
        source_ip=source_ip,
        hostname=hostname,
        severity=severity,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset
    )

    # Add severity level names
    for log in logs:
        log['severity_name'] = SEVERITY_LEVELS.get(log['severity'], 'Unknown')

    return jsonify(logs)


@app.route('/api/login_failures_by_client')
def api_login_failures_by_client():
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with db_pool.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    SELECT
                        client_name,
                        source_ip,
                        COUNT(*)
                    FROM logs
                    WHERE timestamp >= datetime('now', '-1 day')
                      AND LOWER(message) LIKE '%login%'
                      AND LOWER(message) LIKE '%fail%'
                    GROUP BY client_name, source_ip
                    """
                )

                data = cursor.fetchall()

                failure_data = [
                    {
                        'client_name': client_name if client_name else 'Unknown',
                        'source_ip': source_ip if source_ip else 'Unknown',
                        'count': count,
                    }
                    for client_name, source_ip, count in data
                ]

                return jsonify(failure_data)

        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                wait_time = (2 ** attempt) + (time.time() % 1)
                logger.warning(
                    f"Database locked during login failures query, retrying in {wait_time:.2f}s"
                )
                time.sleep(wait_time)
            else:
                logger.error(
                    f"Failed to get login failures data after {max_retries} attempts: {e}"
                )
                return jsonify([])
        except Exception as e:
            logger.error(f"Error getting login failures data: {e}")
            return jsonify([])


@app.route('/api/login_failures_heatmap')
def api_login_failures_heatmap():
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with db_pool.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    SELECT strftime('%H', timestamp) as hour, source_ip, COUNT(*)
                    FROM logs
                    WHERE timestamp >= datetime('now', '-1 day')
                      AND LOWER(message) LIKE '%login%'
                      AND LOWER(message) LIKE '%fail%'
                    GROUP BY hour, source_ip
                    """
                )

                data = cursor.fetchall()

                failure_data = []
                for hour, source_ip, count in data:
                    failure_data.append(
                        {
                            'hour': int(hour),
                            'source_ip': source_ip if source_ip else 'Unknown',
                            'count': count,
                        }
                    )

                return jsonify(failure_data)

        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                wait_time = (2 ** attempt) + (time.time() % 1)
                logger.warning(
                    f"Database locked during login failures heatmap query, retrying in {wait_time:.2f}s"
                )
                time.sleep(wait_time)
            else:
                logger.error(
                    f"Failed to get login failures heatmap data after {max_retries} attempts: {e}"
                )
                return jsonify([])
        except Exception as e:
            logger.error(f"Error getting login failures heatmap data: {e}")
            return jsonify([])


@app.route('/api/performance')
def api_performance():
    """Return server performance metrics."""
    cpu = _read_cpu_usage()
    mem_total, mem_used, mem_percent = _read_memory_usage()
    net_recv, net_send = _read_network_usage()
    return jsonify({
        'cpu_percent': cpu,
        'memory_total': mem_total,
        'memory_used': mem_used,
        'memory_percent': mem_percent,
        'net_recv_rate': net_recv,
        'net_send_rate': net_send,
    })


@app.route('/api/stats')
def api_stats():
    """API endpoint for log statistics"""
    stats = db_manager.get_log_stats()

    # Add severity level names to stats
    severity_stats_named = {}
    for severity, count in stats['severity_stats'].items():
        severity_name = SEVERITY_LEVELS.get(severity, f'Level {severity}')
        severity_stats_named[severity_name] = count

    stats['severity_stats_named'] = severity_stats_named

    return jsonify(stats)


@app.route('/api/export')
def api_export():
    """Export logs as JSON"""
    query = request.args.get('query', '')
    source_ip = request.args.get('source_ip', '')
    hostname = request.args.get('hostname', '')
    severity = request.args.get('severity')
    start_time = request.args.get('start_time', '')
    end_time = request.args.get('end_time', '')

    severity = int(severity) if severity and severity.isdigit() else None

    logs = db_manager.search_logs(
        query=query,
        source_ip=source_ip,
        hostname=hostname,
        severity=severity,
        start_time=start_time,
        end_time=end_time,
        limit=10000,
        offset=0
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(logs, f, indent=2)
        temp_path = f.name

    return send_file(temp_path, as_attachment=True,
                    download_name=f'firewall_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
