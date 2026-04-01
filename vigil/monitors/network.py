"""Network Threat Feed Monitor — planned for v0.3.

Will check outbound DNS queries and connections against public threat intelligence
feeds (abuse.ch URLhaus, Feodo Tracker) and alert on matches.

Not yet implemented. See https://github.com/jawsec/vigil/issues for roadmap.
"""

import logging

logger = logging.getLogger("vigil")


def run(config: dict, once: bool = False) -> None:
    """Placeholder for the network threat feed monitor."""
    logger.info("Network monitor is not yet implemented (planned for v0.3).")
