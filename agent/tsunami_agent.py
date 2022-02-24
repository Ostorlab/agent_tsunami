"""Agent implementation for tsunami scanner."""
import logging

from ostorlab.agent import agent
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.kb import kb
from rich import logging as rich_logging

from agent.tsunami import tsunami

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)


class AgentTsunami(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Tsunami scanner implementation for ostorlab. using ostorlab python sdk.
    For more visit https://github.com/Ostorlab/ostorlab."""

    def process(self, message: msg.Message) -> None:
        """Starts a tsunami scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime."""

        logger.info('processing message of selector : %s', message.selector)
        if message.data['version'] == 6:
            target_type = 'v6'
        elif message.data['version'] == 4:
            target_type = 'v4'
        else:
            raise ValueError(f'Incorrect ip version {message.data["version"]}')

        target = tsunami.Target(address=message.data['host'], version=target_type)
        with tsunami.Tsunami() as tsunami_scanner:
            scan_result = tsunami_scanner.scan(target=target)


            for vulnerability in scan_result['vulnerabilities']:
                # risk_rating will be HIGH for all detected vulnerabilities
                risk_rating = 'HIGH'
                self.report_vulnerability(
                    entry=kb.Entry(
                        title=vulnerability['vulnerability']['title'],
                        risk_rating=risk_rating,
                        short_description=vulnerability['vulnerability']['description'],
                        description=vulnerability['vulnerability']['description'],
                        recommendation = '',
                        references = {},
                        security_issue = True,
                        privacy_issue = False,
                        has_public_exploit = True,
                        targeted_by_malware = True,
                        targeted_by_ransomware = True,
                        targeted_by_nation_state = True
                    ),
                    technical_detail=f'```json\n{scan_result}\n```',
                    risk_rating=risk_rating)


if __name__ == '__main__':
    logger.info('starting agent..')
    AgentTsunami.main()

