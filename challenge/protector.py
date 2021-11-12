from challenge import networkor
from challenge import detector
from challenge import blockor
from challenge import instrumentator
import logging
import time
import sys


def main():

    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

    try:

        instrumentator.start_http_server(8000)

        conns_curr = set()
        scans_curr = dict()
        t = 0

        logging.info("I'm a protector, and I will protect this host!")

        while True:

            # TODO: replace sleep with a non-blocking alternative. signals are not too well handled at the moment.
            time.sleep(10 - time.time() % 10)  # neat trick to sync the code execution at :10s,:20s,:30s,..

            conns_curr, conns_new = networkor.connections(conns_curr=conns_curr)

            scans_curr, scanners = detector.detections(scans_curr=scans_curr,
                                                       conns_new=conns_new,
                                                       time=t)

            blockor.block(scanners=scanners)

            t = t + 10

    except Exception as e:

        print(e)

        sys.exit(1)
