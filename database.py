import sqlite3
import threading
import time
from datetime import datetime, timedelta
from contextlib import contextmanager
import queue
from typing import Dict, List
import logging
import os
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database configuration
DB_PATH = Path(
    os.environ.get("SYSLOG_DB_PATH", Path.home() / "SyslogData" / "firewall_logs.db")
).expanduser().resolve()
LOG_RETENTION_DAYS = 40
# Ensure database directory exists
os.makedirs(DB_PATH.parent, exist_ok=True)

# Queue for incoming logs
log_queue = queue.Queue()


class DatabaseConnectionPool:
    """Thread-safe database connection pool"""

    def __init__(self, db_path: str, max_connections: int = 10):
        self.db_path = db_path
        self.max_connections = max_connections
        self.connections = queue.Queue(maxsize=max_connections)
        self.lock = threading.Lock()
        self._initialize_pool()

    def _initialize_pool(self):
        """Initialize the connection pool"""
        # Ensure database is in WAL mode before creating pool connections
        attempts = 5
        for attempt in range(attempts):
            try:
                tmp_conn = sqlite3.connect(
                    self.db_path,
                    timeout=30.0,
                    check_same_thread=False,
                )
                tmp_conn.execute("PRAGMA journal_mode=WAL")
                tmp_conn.execute("PRAGMA synchronous=NORMAL")
                tmp_conn.close()
                break
            except sqlite3.OperationalError as e:
                # Retry with exponential backoff if database is locked by another
                # process during WAL mode switch
                if attempt == attempts - 1:
                    raise
                backoff = 0.1 * (2 ** attempt)
                logger.warning(
                    f"Failed to set WAL mode (attempt {attempt + 1}/{attempts}): {e}. "
                    f"Retrying in {backoff:.1f}s"
                )
                time.sleep(backoff)

        for _ in range(self.max_connections):
            conn = self._create_connection()
            self.connections.put(conn)

    def _create_connection(self):
        """Create a new database connection with proper settings"""
        conn = sqlite3.connect(
            self.db_path,
            timeout=30.0,  # Increased timeout
            check_same_thread=False  # Allow cross-thread usage
        )

        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA cache_size=10000')
        conn.execute('PRAGMA temp_store=MEMORY')
        conn.execute('PRAGMA busy_timeout=30000')  # 30 second busy timeout

        return conn

    @contextmanager
    def get_connection(self):
        """Get a connection from the pool"""
        conn = None
        try:
            # Try to get a connection with timeout
            conn = self.connections.get(timeout=10)
            yield conn
        except queue.Empty:
            # If no connection available, create a temporary one
            logger.warning("No connection available in pool, creating temporary connection")
            conn = self._create_connection()
            yield conn
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            raise
        finally:
            if conn:
                try:
                    # Return connection to pool or close if it was temporary
                    if self.connections.qsize() < self.max_connections:
                        self.connections.put(conn)
                    else:
                        conn.close()
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass


# Global connection pool
db_pool = None


class DatabaseManager:
    """Manage SQLite database for log storage with improved concurrency."""

    def __init__(self, db_path: str, start_threads: bool = True):
        """Create a new ``DatabaseManager``.

        Parameters
        ----------
        db_path:
            Path to the SQLite database file.
        start_threads:
            Whether to start background threads for batch processing and
            periodic cleanup. Disabling thread creation is useful for unit
            testing where long-lived daemon threads would otherwise run
            indefinitely.
        """

        self.db_path = db_path
        global db_pool
        db_pool = DatabaseConnectionPool(db_path, max_connections=30)
        self.init_database()
        if start_threads:
            self.start_batch_processor()
            self.start_cleanup_thread()

    def init_database(self):
        """Initialize database tables"""
        with db_pool.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    source_ip TEXT,
                    hostname TEXT,
                    client_name TEXT,
                    program TEXT,
                    facility INTEGER,
                    severity INTEGER,
                    message TEXT,
                    raw_message TEXT,
                    logid TEXT,
                    log_type TEXT,
                    log_subtype TEXT,
                    level TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create indexes for better search performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON logs(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hostname ON logs(hostname)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_name ON logs(client_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON logs(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_message ON logs(message)')

            conn.commit()

    def start_batch_processor(self):
        """Start background thread for batch processing log entries"""

        def batch_processor():
            batch_size = 50
            batch_timeout = 5  # seconds
            batch = []
            last_flush = time.time()

            while True:
                try:
                    # Try to get a log entry with timeout
                    try:
                        log_entry = log_queue.get(timeout=1)
                        batch.append(log_entry)
                    except queue.Empty:
                        log_entry = None

                    # Check if we should flush the batch
                    should_flush = (
                        len(batch) >= batch_size or
                        (batch and time.time() - last_flush > batch_timeout)
                    )

                    if should_flush and batch:
                        self.store_logs_batch(batch)
                        batch.clear()
                        last_flush = time.time()

                except Exception as e:
                    logger.error(f"Error in batch processor: {e}")
                    time.sleep(1)

        processor_thread = threading.Thread(target=batch_processor, daemon=True)
        processor_thread.start()
        logger.info("Started batch processor thread")

    def store_logs_batch(self, log_entries: List[Dict]):
        """Store multiple log entries in a single transaction"""
        if not log_entries:
            return

        max_retries = 3
        for attempt in range(max_retries):
            try:
                with db_pool.get_connection() as conn:
                    cursor = conn.cursor()

                    # Use executemany for better performance
                    cursor.executemany('''
                        INSERT INTO logs (timestamp, source_ip, hostname, client_name, program, facility, severity, message, raw_message, logid, log_type, log_subtype, level)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', [
                        (
                            log_entry['timestamp'],
                            log_entry['source_ip'],
                            log_entry['hostname'],
                            log_entry.get('client_name'),
                            log_entry['program'],
                            log_entry['facility'],
                            log_entry['severity'],
                            log_entry['message'],
                            log_entry['raw_message'],
                            log_entry.get('logid'),
                            log_entry.get('log_type'),
                            log_entry.get('log_subtype'),
                            log_entry.get('level')
                        ) for log_entry in log_entries
                    ])

                    conn.commit()
                    logger.debug(f"Stored batch of {len(log_entries)} log entries")
                    break

            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    wait_time = (2 ** attempt) + (time.time() % 1)  # Exponential backoff with jitter
                    logger.warning(f"Database locked, retrying in {wait_time:.2f}s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Failed to store batch after {max_retries} attempts: {e}")
                    raise
            except Exception as e:
                logger.error(f"Error storing log batch: {e}")
                raise

    def search_logs(self, query: str = "", source_ip: str = "", hostname: str = "",
                   severity: int = None, start_time: str = "", end_time: str = "",
                   limit: int = 100, offset: int = 0) -> List[Dict]:
        """Search logs with various filters"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with db_pool.get_connection() as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    where_conditions = []
                    params = []

                    if query:
                        where_conditions.append("(message LIKE ? OR hostname LIKE ? OR program LIKE ? OR client_name LIKE ?)")
                        query_param = f"%{query}%"
                        params.extend([query_param, query_param, query_param, query_param])

                    if source_ip:
                        where_conditions.append("source_ip LIKE ?")
                        params.append(f"%{source_ip}%")

                    if hostname:
                        where_conditions.append("hostname LIKE ?")
                        params.append(f"%{hostname}%")

                    if severity is not None:
                        where_conditions.append("severity = ?")
                        params.append(severity)

                    if start_time:
                        where_conditions.append("timestamp >= ?")
                        params.append(start_time)

                    if end_time:
                        where_conditions.append("timestamp <= ?")
                        params.append(end_time)

                    where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"

                    sql = f'''
                        SELECT * FROM logs
                        WHERE {where_clause}
                        ORDER BY timestamp DESC
                        LIMIT ? OFFSET ?
                    '''

                    params.extend([limit, offset])
                    cursor.execute(sql, params)

                    results = [dict(row) for row in cursor.fetchall()]
                    return results

            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    wait_time = (2 ** attempt) + (time.time() % 1)
                    logger.warning(f"Database locked during search, retrying in {wait_time:.2f}s")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Failed to search logs after {max_retries} attempts: {e}")
                    return []
            except Exception as e:
                logger.error(f"Error searching logs: {e}")
                return []

    def get_log_stats(self) -> Dict:
        """Get log statistics"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with db_pool.get_connection() as conn:
                    cursor = conn.cursor()

                    # Total logs
                    cursor.execute("SELECT COUNT(*) FROM logs")
                    total_logs = cursor.fetchone()[0]

                    # Logs per severity
                    cursor.execute('''
                        SELECT severity, COUNT(*) as count
                        FROM logs
                        GROUP BY severity
                        ORDER BY severity
                    ''')
                    severity_stats = {row[0]: row[1] for row in cursor.fetchall()}

                    # Top sources with hostname (devname)
                    cursor.execute('''
                        SELECT hostname, client_name, source_ip, COUNT(*) as count, MAX(timestamp) as last_seen
                        FROM logs
                        WHERE timestamp >= datetime('now', '-24 hours')
                        GROUP BY hostname, client_name, source_ip
                        ORDER BY count DESC
                        LIMIT 500
                    ''')
                    top_sources = [{
                        'hostname': row[0] or 'Unknown',
                        'client_name': row[1],
                        'ip': row[2],
                        'count': row[3],
                        'last_seen': row[4]
                    } for row in cursor.fetchall()]

                    # Recent activity (last 24 hours)
                    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
                    cursor.execute("SELECT COUNT(*) FROM logs WHERE timestamp >= ?", (yesterday,))
                    recent_logs = cursor.fetchone()[0]

                    # Database file size (include WAL/shm if present)
                    db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
                    for ext in ("-wal", "-shm"):
                        wal_path = f"{self.db_path}{ext}"
                        if os.path.exists(wal_path):
                            db_size += os.path.getsize(wal_path)

                    return {
                        'total_logs': total_logs,
                        'severity_stats': severity_stats,
                        'top_sources': top_sources,
                        'recent_logs': recent_logs,
                        'db_size_bytes': db_size,
                    }

            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    wait_time = (2 ** attempt) + (time.time() % 1)
                    logger.warning(f"Database locked during stats query, retrying in {wait_time:.2f}s")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Failed to get stats after {max_retries} attempts: {e}")
                    break
            except Exception as e:
                logger.error(f"Error getting log stats: {e}")
                break

        # Return default stats if all attempts failed
        return {
            'total_logs': 0,
            'severity_stats': {},
            'top_sources': [],
            'recent_logs': 0
        }

    def cleanup_old_logs(self):
        """Remove logs older than retention period"""
        cutoff_date = (datetime.now() - timedelta(days=LOG_RETENTION_DAYS)).isoformat()

        max_retries = 3
        for attempt in range(max_retries):
            try:
                with db_pool.get_connection() as conn:
                    cursor = conn.cursor()

                    cursor.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff_date,))
                    deleted_count = cursor.rowcount

                    conn.commit()

                    if deleted_count > 0:
                        logger.info(f"Cleaned up {deleted_count} old log entries")
                    break

            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    wait_time = (2 ** attempt) + (time.time() % 1)
                    logger.warning(f"Database locked during cleanup, retrying in {wait_time:.2f}s")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Failed to cleanup after {max_retries} attempts: {e}")
                    break
            except Exception as e:
                logger.error(f"Error during cleanup: {e}")
                break

    def start_cleanup_thread(self):
        """Start background thread for log cleanup"""

        def cleanup_worker():
            while True:
                time.sleep(3600)  # Run every hour
                try:
                    self.cleanup_old_logs()
                except Exception as e:
                    logger.error(f"Error during cleanup: {e}")

        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        logger.info("Started cleanup thread")


# Initialize database manager and connection pool
#
# The manager is created automatically unless the environment variable
# ``SYSLOG_AUTO_START`` is set to ``"0"``. This allows test suites to import
# the module without spawning background threads or touching the real
# filesystem.
AUTO_START_DB = os.environ.get("SYSLOG_AUTO_START", "1") == "1"
db_manager = DatabaseManager(DB_PATH) if AUTO_START_DB else None
