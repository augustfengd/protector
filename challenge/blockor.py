from challenge.instrumentator import block_metrics
import ipaddress
import logging
import subprocess

log = logging.getLogger(__name__)


@block_metrics
def block(scanners: 'set[str]' = set(),
          safelist: 'list[str]' = [
              '10.0.0.0/8',
              '172.16.0.0/12',
              '192.168.0.0/16',
              '127.0.0.0/8']) -> 'set[str]':
    """Configure the host's firewall using iptables.

    Parameters
    ----------
    scanners : set of str
       The list ip addresses requested to be blocked.

    safelist : list of str
       The list of subnets which should be ignored when blocking.

    Returns
    -------
    blocks : set of str
       The list of source ip addresses which were successfully blocked.
    """

    blocks = set()

    for scanner in scanners:

        ip = ipaddress.ip_address(scanner)

        if not any([ip in ipaddress.ip_network(network)
                    for network in safelist]):

            try:

                # iptables checks for an existing rule, exits with 1 if non-existsant.
                c = subprocess.run(["iptables", "-C", "INPUT", "-s", scanner, "-j", "DROP"], capture_output=True)

                if c.returncode == 1:

                    log.info(f"Blocking scanner ip: {scanner}")

                    r = subprocess.run(["iptables", "-A", "INPUT", "-s", scanner, "-j", "DROP"], capture_output=True)

                    if r.returncode == 0:

                        blocks.add(scanner)

                    else:

                        log.error(r.stderr)

                elif c.returncode == 0:

                    log.warning(f"Already blocked scanner ip: {scanner}."
                                f"Matching rule exists.")

                else:

                    log.error(c.stderr)

            except FileNotFoundError:

                log.error(f"Failing to block scanner: {scanner}."
                          f"iptables not found.")

        else:
            log.info(f"Ignoring scanner ip: {scanner}, "
                     f"because ip is in safelist {safelist}.")

    return blocks
