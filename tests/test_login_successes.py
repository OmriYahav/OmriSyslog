import datetime
import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_login_successes_by_client(tmp_path, monkeypatch):
    pytest.importorskip("flask")
    pytest.importorskip("flask_socketio")
    db_file = tmp_path / 'logs.db'
    monkeypatch.setenv('SYSLOG_DB_PATH', str(db_file))
    monkeypatch.setenv('SYSLOG_AUTO_START', '0')

    database = importlib.reload(importlib.import_module('database'))
    dm = database.DatabaseManager(str(db_file), start_threads=False)
    database.db_manager = dm

    log_entry = {
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'source_ip': '1.2.3.4',
        'hostname': 'fw',
        'client_name': 'clientA',
        'program': 'auth',
        'facility': 1,
        'severity': 3,
        'message': 'user login success',
        'raw_message': 'user login success',
        'logid': '1',
        'log_type': 'event',
        'log_subtype': 'auth',
        'level': 'info',
    }

    dm.store_logs_batch([log_entry])

    webapp = importlib.reload(importlib.import_module('webapp'))

    with webapp.app.test_client() as client:
        resp = client.get('/api/login_successes_by_client')
        assert resp.status_code == 200
        assert resp.get_json() == [
            {'client_name': 'clientA', 'source_ip': '1.2.3.4', 'count': 1}
        ]
