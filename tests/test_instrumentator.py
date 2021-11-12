from challenge.networkor import connections
from prometheus_client import REGISTRY
import pytest

def test_connections_metrics_single_visit():

    conns_curr = set()

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.0")

    assert (len(conns_curr), len(conns_new)) == (0, 0)

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.1")

    assert (len(conns_curr), len(conns_new)) == (1, 1)

    for conns in conns_new:

        l_ip, _, r_ip, _ = conns

        sample_value = REGISTRY.get_sample_value(name="protector_connections_total",
                                                 labels={'l_ip': l_ip, 'r_ip': r_ip})

        assert sample_value == 1.0


def test_connections_metrics_frequent_visitor():

    conns_curr = set()

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.0")

    assert (len(conns_curr), len(conns_new)) == (0, 0)

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.1")

    assert (len(conns_curr), len(conns_new)) == (1, 1)

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.2")

    assert (len(conns_curr), len(conns_new)) == (2, 1)

    for conns in conns_new:

        l_ip, _, r_ip, _ = conns

        sample_value = REGISTRY.get_sample_value(name="protector_connections_total",
                                                 labels={'l_ip': l_ip, 'r_ip': r_ip})

        assert sample_value == 2.0

#@pytest.mark.usefixtures('reset')
def test_connections_metrics_scans():

    conns_curr = set()

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.0")

    assert (len(conns_curr), len(conns_new)) == (0, 0)

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.1")

    assert (len(conns_curr), len(conns_new)) == (1, 1)

    conns_curr, conns_new = connections(conns_curr=conns_curr, tcp4_seq_file="tests/mockdata/proc.net.tcp.frequentvisitor.2")

    assert (len(conns_curr), len(conns_new)) == (2, 1)

    for conns in conns_new:

        l_ip, _, r_ip, _ = conns

        sample_value = REGISTRY.get_sample_value(name="protector_connections_total",
                                                 labels={'l_ip': l_ip, 'r_ip': r_ip})

        assert sample_value == 2.0
