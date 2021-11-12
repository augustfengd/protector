from prometheus_client import start_http_server  # noqa: F401, reason: used indirectly in challenge.protector
from prometheus_client import Counter


def connections_metrics(func):
    """Instrumentalize the connections function"""

    connections_total = Counter(name='protector_connections',
                                documentation='Number of total new connections established.',
                                labelnames=('l_ip', 'r_ip'))

    def connections(**kwargs):

        nonlocal connections_total

        conns_all, conns_new = func(**kwargs)

        for conns in conns_new:

            l_ip, _, r_ip, _ = conns

            connections_total.labels(l_ip, r_ip).inc()

        return (conns_all, conns_new)

    return connections


def block_metrics(func):
    """passthrough for now."""

    def blockor(**kwargs):

        blocks = func(**kwargs)

        return blocks

    return blockor


def detections_metrics(func):
    """passthrough for now."""

    def detector(**kwargs):

        scans_curr, scanners = func(**kwargs)

        return (scans_curr, scanners)

    return detector
