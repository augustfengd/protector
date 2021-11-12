from challenge.networkor import socket_pair, hex_to_ip, hex_to_port, connections
import logging

# Helper functions

def isValidPort(port):

    return 0 < int(port) <= 65535


def isValidIp(ip):

    return all([0 <= int(o) <= 255 for o in ip.split(".")]) and len(ip.split(".")) == 4


# Tests

def test_socket_pair():
    """Normal use case test."""

    local_address = "3500007F:0035"
    remote_address = "00000000:0001"

    l_ip, l_port, r_ip, r_port = socket_pair(local_address, remote_address)

    assert isValidPort(l_port)
    assert isValidIp(l_ip)
    assert isValidPort(r_port)
    assert isValidIp(r_ip)


def test_hex_to_ip():
    """Normal use case test."""

    ip_h = "0100007F"
    ip_s = hex_to_ip(ip_h)

    assert isValidIp(ip_s)


def test_hex_to_ip_invalid_hex():
    """Invalid hex should return empty string."""

    ip_h = "0100007H"
    ip_s = hex_to_ip(ip_h)

    assert ip_s == ""


def test_hex_to_ip_empty_input():
    """Empty input should return empty string."""

    ip_h = ""
    ip_s = hex_to_ip(ip_h)

    assert ip_s == ""


def test_hex_to_port():
    """Normal use test case."""
    port_h = "0050"

    port_s = hex_to_port(port_h)

    assert 0 < int(port_s) < 65535


def test_hex_to_port_invalid_hex():
    """Invalid hex should return empty string."""

    port_h = "005H"

    port_s = hex_to_port(port_h)

    assert port_s == ""


def test_connections_one():
    """First value should accumulate the active connections, and second value should only include newer connections."""

    conns_curr = set()

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.0")

    assert (len(conns_curr), len(conns_new)) == (0, 0)

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.1")

    assert (len(conns_curr), len(conns_new)) == (1, 1)


def test_connections_one_logging(caplog):
    """One connection should log once."""
    conns, _ = connections(conns_curr=set(), tcp4_seq_file="tests/mockdata/proc.net.tcp.0")

    conns, _ = connections(conns_curr=conns, tcp4_seq_file="tests/mockdata/proc.net.tcp.1")

    assert sum(["New connection:" in message for message in caplog.messages]) == 1


def test_connections_two():
    """First value should accumulate the active connections, and second value should only include newer connections."""

    conns_curr = set()

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.0")

    assert (len(conns_curr), len(conns_new)) == (0, 0)

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.1")

    assert (len(conns_curr), len(conns_new)) == (1, 1)

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.2")

    assert (len(conns_curr), len(conns_new)) == (2, 1)


def test_connections_two_logging(caplog):
    """Each connection should only log once."""

    conns_curr = set()

    conns_curr, _ = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.0")

    conns_curr, _ = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.1")

    conns_curr, _ = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.2")

    assert sum(["New connection:" in message for message in caplog.messages]) == 2


def test_connections_two_persistent():
    """Persistent connections should not be considered new on subsequent runs."""

    conns_curr = set()

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.0")

    assert (len(conns_curr), len(conns_new)) == (0, 0)

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.1")

    assert (len(conns_curr), len(conns_new)) == (1, 1)

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.2")

    assert (len(conns_curr), len(conns_new)) == (2, 1)

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.2")

    assert (len(conns_curr), len(conns_new)) == (2, 0)


def test_connections_two_persistent_logging(caplog):
    """Persistent connections should not log twice."""

    conns_curr = set()

    conns_curr, _ = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.0")

    conns_curr, _ = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.1")

    conns_curr, _ = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.2")

    conns_curr, _ = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.2")

    assert sum(["New connection:" in message for message in caplog.messages]) == 2
