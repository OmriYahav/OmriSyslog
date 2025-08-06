import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from handler import SyslogHandler


def test_parse_syslog_basic():
    message = (
        '<34>2023-01-01T00:00:00 '
        'devname="FW1" client_name="ClientA" '
        'logid="1234" type="traffic" subtype="forward" '
        'level="warning" some message'
    )
    result = SyslogHandler.parse_syslog(message, '1.2.3.4')

    assert result['hostname'] == 'FW1'
    assert result['client_name'] == 'ClientA'
    assert result['logid'] == '1234'
    assert result['log_type'] == 'traffic'
    assert result['log_subtype'] == 'forward'
    assert result['severity'] == 4
    assert result['timestamp'].startswith('2023-01-01T00:00:00')
    assert result['program'] == 'traffic/forward'

