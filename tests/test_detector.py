from challenge.networkor import connections
from challenge.detector import detections


def test_detections_noscans():
    """A single connection should not be considered as a port scan."""

    conns_curr = set()
    scans_curr = dict()

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.0")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    assert len(scanners) == 0

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    assert len(scanners) == 0

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    assert len(scanners) == 0

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    assert len(scanners) == 0

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    assert len(scanners) == 0

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    assert len(scanners) == 0

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    assert len(scanners) == 0


def test_detections_noscans_logging(caplog):
    """A single connection should not be considered as a port scan, and should not log anything."""

    conns_curr = set()
    scans_curr = dict()

    # mock a single new connection only at 10s.

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.0")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    assert sum(["Port scan detected:" in message for message in caplog.messages]) == 0


def test_detections_frequent_visitor():
    """Frequent connections onto the same port should not be considered a port scan."""

    conns_curr = set()
    scans_curr = dict()

    # mock connections from a fixed ip address at 0s, 10s, 20s, 30s, 40s, 50s, 60s.

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    assert len(scanners) == 0

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.2")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    assert len(scanners) == 0

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    assert len(scanners) == 0

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.4")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    assert len(scanners) == 0

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.5")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    assert len(scanners) == 0

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.6")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    assert len(scanners) == 0

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.7")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    assert len(scanners) == 0


def test_detections_frequent_visitor_logging(caplog):
    """Frequent connections onto the same port should not be considered a port scan, and should not log anything."""

    conns_curr = set()
    scans_curr = dict()

    # mock connections from a fixed ip address at 0s, 10s, 20s, 30s, 40s, 50s, 60s.

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.2")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.3")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.4")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.5")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.6")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.7")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    assert sum(["Port scan detected:" in message for message in caplog.messages]) == 0


def test_detections_scans():
    """A remote host who scans more than 3 different ports should be flagged as a scanner with each subsequent scan that is greater than 3."""

    # mock a scanner who scans at 0s, 20s, 40s and 60s

    conns_curr = set()
    scans_curr = dict()

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    assert len(scanners) == 0

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    assert len(scanners) == 0

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.2")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    assert len(scanners) == 0

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.2")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    assert len(scanners) == 0

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    assert len(scanners) == 0

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    assert len(scanners) == 0

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.4")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    assert len(scanners) == 1

    # t 7
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.4")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=70)

    assert len(scanners) == 0

    # t 8
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.4")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=80)

    assert len(scanners) == 0


def test_detections_scans_logging(caplog):
    """A remote host who scans more than 3 different ports should raise a log trace with each subsequent scan."""

    # mock a scanner who scans at 0s, 20s, 40s and 60s

    conns_curr = set()
    scans_curr = dict()

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    assert len(scanners) == 0

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    assert len(scanners) == 0

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.2")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    assert len(scanners) == 0

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.2")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    assert len(scanners) == 0

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    assert len(scanners) == 0

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    assert len(scanners) == 0

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.4")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    assert len(scanners) == 1

    assert sum(["Port scan detected:" in message for message in caplog.messages]) == 1


def test_detections_dense_scans():
    """Heavy scanning (>3 scans within 60s) from a host should be considered a port scan with each subsequent scan that is greater than 3."""

    # mock a scanner who scans at 0s, 10s, 20s, 30s and 40s

    conns_curr = set()
    scans_curr = dict()

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    assert len(scanners) == 0

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.2")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    assert len(scanners) == 0

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    assert len(scanners) == 0

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.4")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    assert len(scanners) == 1

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.4")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    assert len(scanners) == 0

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.5")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    assert len(scanners) == 1

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.5")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    assert len(scanners) == 0


def test_detections_scans_heavy_logging(caplog):
    """Heavy scanning (>3 scans within 60s) from a host should be log a port scan with each subsequent scan that is greater than 3."""

    # mock a scanner who scans at 0s, 10s, 20s, 30s and 40s

    conns_curr = set()
    scans_curr = dict()

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    assert len(scanners) == 0

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.2")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    assert len(scanners) == 0

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    assert len(scanners) == 0

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.4")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    assert len(scanners) == 1

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.5")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    assert len(scanners) == 1

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.5")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    assert len(scanners) == 0

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.5")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    assert len(scanners) == 0

    assert sum(["Port scan detected:" in message for message in caplog.messages]) == 2


def test_detections_expired_scans():
    """Port scans that are older than 60s should not be considered into calculation when detecting port scans."""

    # mock a scanner who scans at 0s, 20s, 40s and 70s

    conns_curr = set()
    scans_curr = dict()

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    assert len(scanners) == 0

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    assert len(scanners) == 0

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.2")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    assert len(scanners) == 0

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.2")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    assert len(scanners) == 0

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    assert len(scanners) == 0

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    assert len(scanners) == 0

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    assert len(scanners) == 0

    # t 7
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=70)

    assert len(scanners) == 0

    # t 8
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=80)

    assert len(scanners) == 0


def test_detections_expired_scans_logging(caplog):
    """Port scans that are older than 60s should not be considered into calculations when detecting port scans, and there should not be any logs either."""

    # mock a scanner who scans at 0s, 20s, 40s and 70s

    conns_curr = set()
    scans_curr = dict()

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.2")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.2")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    # t 7
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.3")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=70)

    assert sum(["Port scan detected:" in message for message in caplog.messages]) == 0


def test_detections_expired_scans_all():
    """Port scans that are older than 60s should not be considered into calculations when detecting port scans."""

    # mock a scanner who scans at 0s, 20s, 40s and 70s

    conns_curr = set()
    scans_curr = dict()

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    assert len(scanners) == 0

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    assert len(scanners) == 0

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    assert len(scanners) == 0

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    assert len(scanners) == 0

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    assert len(scanners) == 0

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    assert len(scanners) == 0

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    assert len(scanners) == 0

    # t 7
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, scanners = detections(scans_curr=scans_curr, conns_new=conns_new, time=70)

    assert len(scanners) == 0


def test_detections_expired_scans_all_logging(caplog):
    """Port scans that are older than 60s should not be considered into calculations when detecting port scans, and there should not be any logs either."""

    # mock a scanner who scans at 0s, 20s, 40s and 70s

    conns_curr = set()
    scans_curr = dict()

    # t 0
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=0)

    # t 1
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=10)

    # t 2
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=20)

    # t 3
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=30)

    # t 4
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=40)

    # t 5
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=50)

    # t 6
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=60)

    # t 7
    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.portscans.1")
    scans_curr, _ = detections(scans_curr=scans_curr, conns_new=conns_new, time=70)

    assert sum(["Port scan detected:" in message for message in caplog.messages]) == 0
