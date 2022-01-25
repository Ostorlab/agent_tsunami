"""Agent implementation for tsunami scanner."""

from ostorlab.agent import agent
from ostorlab.agent.message import message as msg
from tsunami import tsunami
import logging
from rich.logging import RichHandler


logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')


class AgentTsunami(agent.Agent):
    """Tsunami scanner implementation for ostorlab. using ostorlab python sdk.
    For more visit https://github.com/Ostorlab/ostorlab .
    """

    def process(self, message: msg.Message) -> None:
        """Based on the type of the selector, starts a tsunami scan, wait for the scan to finish,
        and emit the results."""

        logger.info('Received a new message, processing...')
        if message['selector'] == 'v3.network.ip':
            if message['data']['version'] == 6:
                target_type = 'v6'
            else:
                target_type = 'v4'
            tsunami_scanner = tsunami.Tsunami(target=message['data']['host'], target_type=target_type)
            scan_res = tsunami_scanner.scan()
            del scan_res


if __name__ == '__main__':
    logger.info('starting tsunami agent ...')
    AgentTsunami.start()
