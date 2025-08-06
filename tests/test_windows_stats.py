import types
import math
import sys
import importlib
from pathlib import Path


def _import_webapp(monkeypatch):
    class DummyFlask:
        def __init__(self, *a, **k):
            self.config = {}

        def route(self, *a, **k):
            def decorator(func):
                return func
            return decorator

    flask_stub = types.SimpleNamespace(
        Flask=DummyFlask,
        jsonify=lambda *a, **k: None,
        render_template=lambda *a, **k: None,
        request=None,
        send_file=lambda *a, **k: None,
    )
    socketio_stub = types.SimpleNamespace(
        SocketIO=lambda app, **k: types.SimpleNamespace(
            emit=lambda *a, **k: None,
            start_background_task=lambda target: None,
            sleep=lambda *a, **k: None,
        )
    )
    monkeypatch.setitem(sys.modules, 'flask', flask_stub)
    monkeypatch.setitem(sys.modules, 'flask_socketio', socketio_stub)
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    return importlib.reload(importlib.import_module('webapp'))


def _make_filetime(val):
    return val & 0xFFFFFFFF, val >> 32


def test_windows_cpu_usage_without_psutil(monkeypatch):
    webapp = _import_webapp(monkeypatch)
    monkeypatch.setattr(webapp, 'psutil', None)
    monkeypatch.setattr(webapp, 'os', types.SimpleNamespace(name='nt'))

    class DummyKernel32:
        def __init__(self):
            self.values = [
                (100, 200, 300),
                (150, 250, 350),
            ]

        def GetSystemTimes(self, idle_p, kernel_p, user_p):
            idle, kernel, user = self.values.pop(0)
            idle_p._obj.dwLowDateTime, idle_p._obj.dwHighDateTime = _make_filetime(idle)
            kernel_p._obj.dwLowDateTime, kernel_p._obj.dwHighDateTime = _make_filetime(kernel)
            user_p._obj.dwLowDateTime, user_p._obj.dwHighDateTime = _make_filetime(user)
            return 1

    monkeypatch.setattr(
        webapp.ctypes,
        'windll',
        types.SimpleNamespace(kernel32=DummyKernel32()),
        raising=False,
    )

    webapp._last_cpu = None
    first = webapp._read_cpu_usage()
    second = webapp._read_cpu_usage()
    assert first == 0.0
    assert math.isclose(second, 50.0, rel_tol=1e-3)


def test_windows_memory_usage_without_psutil(monkeypatch):
    webapp = _import_webapp(monkeypatch)
    monkeypatch.setattr(webapp, 'psutil', None)
    monkeypatch.setattr(webapp, 'os', types.SimpleNamespace(name='nt'))

    class DummyKernel32:
        def GlobalMemoryStatusEx(self, status_p):
            status = status_p._obj
            status.dwLength = 0
            status.ullTotalPhys = 1024
            status.ullAvailPhys = 512
            status.dwMemoryLoad = 50
            return 1

    monkeypatch.setattr(
        webapp.ctypes,
        'windll',
        types.SimpleNamespace(kernel32=DummyKernel32()),
        raising=False,
    )

    total, used, percent = webapp._read_memory_usage()
    assert total == 1024
    assert used == 512
    assert percent == 50.0


def test_windows_network_usage_without_psutil(monkeypatch):
    webapp = _import_webapp(monkeypatch)
    monkeypatch.setattr(webapp, 'psutil', None)
    monkeypatch.setattr(webapp, 'os', types.SimpleNamespace(name='nt'))

    outputs = iter([
        "Interface Statistics\n\n                           Received            Sent\n\nBytes                    1000               2000\n",
        "Interface Statistics\n\n                           Received            Sent\n\nBytes                    3000               7000\n",
    ])

    monkeypatch.setattr(
        webapp.subprocess, 'check_output', lambda *a, **k: next(outputs)
    )
    times = iter([1, 2])
    monkeypatch.setattr(webapp.time, 'time', lambda: next(times))

    webapp._last_net = None
    first = webapp._read_network_usage()
    second = webapp._read_network_usage()
    assert first == (0.0, 0.0)
    assert second == (2000.0, 5000.0)
