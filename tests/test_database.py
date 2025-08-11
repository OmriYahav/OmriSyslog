import importlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_store_and_search(tmp_path, monkeypatch):
    db_file = tmp_path / 'logs.db'
    monkeypatch.setenv('SYSLOG_DB_PATH', str(db_file))
    monkeypatch.setenv('SYSLOG_AUTO_START', '0')

    database = importlib.reload(importlib.import_module('database'))
    dm = database.DatabaseManager(str(db_file), start_threads=False)

    log_entry = {
        'timestamp': '2023-01-01T00:00:00',
        'source_ip': '1.2.3.4',
        'hostname': 'fw',
        'client_name': 'client',
        'program': 'firewall',
        'facility': 1,
        'severity': 3,
        'message': 'test message',
        'raw_message': 'test message',
        'logid': '123',
        'log_type': 'traffic',
        'log_subtype': 'forward',
        'level': 'warning',
    }

    dm.store_logs_batch([log_entry])

    results = dm.search_logs(query='test message')
    assert len(results) == 1
    assert results[0]['message'] == 'test message'

    stats = dm.get_log_stats()
    assert stats['total_logs'] == 1
    assert stats['severity_stats'][3] == 1
    assert stats['db_size_bytes'] > 0


def test_pool_initializes_wal_mode(tmp_path):
    from database import DatabaseConnectionPool
    db_file = tmp_path / 'logs.db'

    # Should not raise OperationalError during initialization
    pool = DatabaseConnectionPool(str(db_file), max_connections=2)

    with pool.get_connection() as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"

    # New connections should inherit WAL mode without explicitly setting it
    import sqlite3

    conn2 = sqlite3.connect(str(db_file))
    mode2 = conn2.execute("PRAGMA journal_mode").fetchone()[0]
    conn2.close()
    assert mode2.lower() == "wal"


def test_wal_initialization_succeeds_with_locked_db(tmp_path):
    """Simulate a locked database and ensure WAL initialization succeeds."""
    from database import DatabaseConnectionPool
    import sqlite3
    import threading
    import time

    db_file = tmp_path / 'locked.db'

    # Acquire an exclusive lock on the database
    locker = sqlite3.connect(str(db_file), check_same_thread=False)
    locker.execute("BEGIN EXCLUSIVE")

    def release_lock():
        time.sleep(1)
        locker.execute("COMMIT")
        locker.close()

    t = threading.Thread(target=release_lock)
    t.start()

    # Should block until the lock is released and then succeed
    pool = DatabaseConnectionPool(str(db_file), max_connections=1)
    t.join()

    with pool.get_connection() as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"

