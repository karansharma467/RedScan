import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src")
)

import redscan


def test_parse_ports():
    ports = redscan.parse_ports("22,80,443")
    assert ports == [22, 80, 443]


def test_parse_port_range():
    ports = redscan.parse_ports("80-82")
    assert ports == [80, 81, 82]


def test_validate_target():
    result = redscan.validate_target("127.0.0.1")
    assert result == "127.0.0.1"


def test_identify_service():
    result = redscan.identify_service(80)
    assert result == "http"


def test_reverse_dns():
    result = redscan.reverse_dns("127.0.0.1")
    assert result == "localhost"
