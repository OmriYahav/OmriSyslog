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

