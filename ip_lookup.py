from dotenv import load_dotenv
import os
import json
import logging

import ipinfo

load_dotenv()
IPINFO_TOKEN = os.getenv('IPINFO_TOKEN')


def setup_logger(log_file='ip.log'):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    if log_file is None:
        # use stdout
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        logger.addHandler(stream_handler)
    else:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)
        
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    for handler in logger.handlers:
        handler.setFormatter(formatter)

    return logger


if __name__ == "__main__":
    logger = setup_logger(log_file=None)

    with open('data/tokyo_hosts.json', 'r') as f:
        known_hosts = json.loads(f.read())

    handler = ipinfo.getHandler(IPINFO_TOKEN)

    for ip, dns_record in sorted(known_hosts.items()):
        logger.info(f"KNOWN: {ip}, {dns_record}")
        logger.info("-----")

        detail = handler.getDetails(ip)
        for prop in ['hostname', 'city', 'country', 'loc', 'org']:
            if hasattr(detail, prop):
                logger.info(f"{prop:9}: {getattr(detail, prop)}")

        logger.info("=====")

