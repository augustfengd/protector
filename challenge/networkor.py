from challenge.instrumentator import connections_metrics
import logging

log = logging.getLogger(__name__)


def socket_pair(l_socket: str = "",
                r_socket: str = "") -> 'tuple[str,str,str,str]':
    """Return a 4-tuple socket pair based on a pair of string represented sockets."""

    # ephemeral function for some elegant destructuring
    def parse_socket_string(ip, port):
        return hex_to_ip(ip), hex_to_port(port)

    l_ip, l_port = parse_socket_string(*l_socket.split(":"))
    r_ip, r_port = parse_socket_string(*r_socket.split(":"))

    return (l_ip, l_port, r_ip, r_port)


def hex_to_ip(h: str = "") -> str:
    """Return an ip address in dotted-decimal format from a hexadecimal form (little-endian twist too)."""

    try:
        return ".".join(
            (
                str(int(h[6:8], 16)),
                str(int(h[4:6], 16)),
                str(int(h[2:4], 16)),
                str(int(h[0:2], 16))
            )
        )

    except ValueError:

        if len(h) == "":

            logging.error("Hexadecimal string for IP is empty.")

        else:

            logging.error("Cannot convert invalid hexadecimal string.")

    return ""


def hex_to_port(h: str = "") -> str:
    """Return a port number from a hexadecimal form."""

    try:

        return str(int(h, 16))

    except ValueError:

        if len(h) == "":

            log.error("Hexadecimal string for port is empty.")

        else:

            log.error("Cannot convert invalid hexadecimal string.")

    return ""


@connections_metrics
def connections(conns_curr: set = set(),
                tcp4_seq_file: str = "/proc/net/tcp",
                ephemeral_ports_min: int = 32768,
                ephemeral_ports_max: int = 60999) -> 'tuple[set[tuple[str,str,str,str]], set[tuple[str,str,str,str]]]':
    """Log new incoming tcp connections by monitoring /proc/net/tcp.

    Parameters
    ----------
    conns_curr : set of (tuple of (str, str, str, str))
        A set of current connections, where each connection is a 4-tuple socket pairs.

    tcp4_seq_file : str
        A file path which points to the ipv4 interface file.

    ephemeral_ports_min : int
        Lower bound of the ephemeral ports range.

    ephemeral_ports_max : int
        Upper bound of the ephemeral ports range.

    Returns
    -------
    conns_all : set of (tuple of (str, str, str, str))
        An updated set of current connections, where each connection is a 4-tuple socket pairs.

    conns_new : set (tuple of (str, str, str, str))
       A set of _new_ connections, where each connection is a 4-tuple socket pairs.
    """

    conns_all = set()
    conns_new = set()

    with open(tcp4_seq_file, "r") as f:

        seq_header = f.readline().split()
        if (seq_header[1], seq_header[2]) != ("local_address", "rem_address"):

            raise ValueError("Could not find columns "
                             "'local_address', 'rem_address' and 'st' "
                             "in expected header columns.")

        while (line := f.readline().split()):

            local_address, remote_address = (line[1], line[2])

            conn = socket_pair(local_address, remote_address)

            l_ip, l_port, r_ip, r_port = conn

            if (ephemeral_ports_min <= int(r_port) <= ephemeral_ports_max):

                if conn not in conns_curr:

                    log.info(f"New connection: "
                             f"{r_ip}:{r_port} -> {l_ip}:{l_port}")

                    conns_new.add(conn)

                conns_all.add(conn)

    return (conns_all, conns_new)
