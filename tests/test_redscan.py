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
def test_invalid_port_text():
    try:
        redscan.parse_ports("abc")
        assert False
    except ValueError as error:
        assert str(error) == "Invalid port value: abc"


def test_invalid_port_zero():
    try:
        redscan.parse_ports("0")
        assert False
    except ValueError as error:
        assert str(error) == "Invalid port value: 0"


def test_invalid_port_too_large():
    try:
        redscan.parse_ports("70000")
        assert False
    except ValueError as error:
        assert str(error) == "Invalid port value: 70000"


def test_invalid_port_range():
    try:
        redscan.parse_ports("100-50")
        assert False
    except ValueError as error:
        assert str(error) == "Invalid port range: 100-50"
