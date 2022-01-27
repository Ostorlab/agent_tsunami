"""Agent implementation for tsunami scanner."""
import logging

from ostorlab.agent import agent
from ostorlab.agent.message import message as msg
from rich import logging as rich_logging

from agent.tsunami import tsunami

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')


class AgentTsunami(agent.Agent):
    """Tsunami scanner implementation for ostorlab. using ostorlab python sdk.
    For more visit https://github.com/Ostorlab/ostorlab."""

    def process(self, message: msg.Message) -> None:
        """Starts a tsunami scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime."""

        logger.info('Received a new message, processing...')
        if message.data['version'] == 6:
            target_type = 'v6'
        elif message.data['version'] == 4:
            target_type = 'v4'
        else:
            raise ValueError(f'Incorrect ip version {message.data["version"]}')

        target = tsunami.Target(address=message.data['host'], version=target_type)
        with tsunami.Tsunami() as tsunami_scanner:
            scan_result = tsunami_scanner.scan(target=target)
            logger.info('Scan finished Number of finding %s', len(scan_result['vulnerabilities']))


if __name__ == '__main__':
    logger.info('Starting Tsunami agent...')
    AgentTsunami.main()
