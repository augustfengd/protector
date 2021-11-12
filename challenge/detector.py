from challenge.instrumentator import detections_metrics
from collections import deque
import logging

log = logging.getLogger(__name__)


@detections_metrics
def detections(scans_curr: 'dict[tuple[str,str],deque[tuple[int,str]]]' = dict(),
               conns_new: 'set[tuple[str,str,str,str]]' = set(),
               time: int = 0) -> 'tuple[dict[tuple[str,str],deque[tuple[int,str]]], set[str]]':
    """Detect port scanners based on historical scans.

    Parameters
    ----------
    scans_curr : dict of {tuple of (str,str): deque of (tuple of (integer, str))}
       The historical data of past scans.

    conns_new : set of (tuple of (str, str, str, str))
       A set of 4-tuple socket pairs representing new probing activities.

    time : int
       The new iteration time.

    Returns
    -------
    scans_curr : dict of {tuple of (str,str): deque of tuple of (integer, str)}
       The newly updated historical data of past scans.

    scanners : set of str
       A set of IP addresses that identify port scanners.
    """

    scanners = set()

    # add new connections into scans history.
    for l_ip, l_port, r_ip, _ in conns_new:

        scan = (time, l_port)

        if (l_ip, r_ip) not in scans_curr:

            scans_curr[(l_ip, r_ip)] = deque([scan])

        else:

            scans_curr[(l_ip, r_ip)].append(scan)

    # iterate through the scan history for potential port scanners.
    for ip_pair, scans in scans_curr.items():

        local_ip, remote_ip = ip_pair

        scanned_ports = set()

        # pop expired scans.
        while scans:

            scan_time, _ = scans[0]

            if time - scan_time > 60:

                scans_curr[ip_pair].popleft()

            else:

                break

        # build a list of scanned ports with the remaining scanners' scan history.
        for scan_time, l_port in scans:

            scanned_ports.add(l_port)

        if len(scanned_ports) > 3:

            scan_time_latest, _ = scans[-1]

            # log new scanner and build scanner ip list.
            if scan_time_latest == time:

                log.info(f"Port scan detected: "
                         f"{local_ip} -> {remote_ip} on ports {sorted(scanned_ports)}")

                scanners.add(remote_ip)

    return (scans_curr, scanners)
