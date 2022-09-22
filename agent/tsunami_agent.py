"""Agent implementation for tsunami scanner."""
import ipaddress
import logging
from typing import List, Union
from urllib import parse
import re
from typing import Optional

from ostorlab.agent import agent
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
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


def _should_process_url(scope_urls_regex: Optional[str], url: str) -> bool:
    if scope_urls_regex is None:
        return True
    link_in_scan_domain = re.match(scope_urls_regex, url) is not None
    if not link_in_scan_domain:
        logger.warning('link url %s is not in domain %s', url, scope_urls_regex)
    return link_in_scan_domain


def _prepare_domain_name_and_url(message: msg.Message, scope_urls_regex: Optional[str]) -> Union[str, None]:
    """Prepare domain name based on type, if url is provided, return its domain."""
    if (domain_name := message.data.get('name')) is not None:
        return str(message.data['name']) if _should_process_url(scope_urls_regex, domain_name) else None
    elif (url := message.data.get('url')) is not None:
        return str(parse.urlparse(message.data['url']).netloc) if _should_process_url(scope_urls_regex,
                                                                                      url) else None
    else:
        return None


def _prepare_targets(message: msg.Message, scope_urls_regex: Optional[str]) -> List[tsunami.Target]:
    """Prepare Targets and dispatch it to prepare:"""
    """domain/link"""
    if (domain := _prepare_domain_name_and_url(message, scope_urls_regex)) is not None:
        return [tsunami.Target(domain=domain)]
    """host"""
    if message.data.get('host') is not None:
        version = message.data['version']
        if version == 6:
            version = 'v6'
        elif message.data['version'] == 4:
            version = 'v4'
        else:
            raise ValueError(f'Incorrect ip version {message.data["version"]}')
        try:
            if message.data.get('mask') is None:
                ip_network = ipaddress.ip_network(message.data['host'])
            else:
                ip_network = ipaddress.ip_network(f"""{message.data.get('host')}/{message.data.get('mask')}""")
            return [tsunami.Target(version=version, address=str(host)) for host in ip_network.hosts()]
        except ValueError:
            logger.info('Incorrect %s / %s', {message.data.get('host')}, {message.data.get('mask')})
            return []
    else:
        return []


class AgentTsunami(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin, persist_mixin.AgentPersistMixin):
    """Tsunami scanner implementation for ostorlab. using ostorlab python sdk.
    For more visit https://github.com/Ostorlab/ostorlab."""

    def __init__(self,
                 agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings
                 ) -> None:
        super().__init__(agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self._scope_urls_regex: Optional[str] = self.args.get('scope_urls_regex')

    def _check_asset_was_added(self, targets: tsunami.Target) -> bool:
        """Check if the asset was scanned before or not"""
        if targets.domain is not None:
            if self.set_add(b'agent_tsunami', f'{targets.domain}'):
                logger.info('target %s/ was processed before, exiting', targets.domain)
                return False
        return True

    def process(self, message: msg.Message) -> None:
        """Starts a tsunami scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime."""

        logger.info('processing message of selector : %s', message.selector)
        if message.data.get('host') is not None:
            host = message.data.get('host')
            mask = message.data.get('mask')
            if mask is not None:
                addresses = ipaddress.ip_network(f'{host}/{mask}')
            else:
                addresses = ipaddress.ip_network(f'{host}')
            if not self.add_ip_network('agent_tsunami', addresses):
                logger.info('target %s was processed before, exiting', addresses)
                return

        targets = _prepare_targets(message=message, scope_urls_regex=self._scope_urls_regex)
        for target in targets:
            if target.domain is not None:
                if self._check_asset_was_added(target) is True:
                    return
            with tsunami.Tsunami() as tsunami_scanner:
                scan_result = tsunami_scanner.scan(target=target)
                logger.info('found %d vulnerabilities', len(scan_result.get('vulnerabilities', [])))
                for vulnerability in scan_result.get('vulnerabilities', {}):
                    # risk_rating will be HIGH for all detected vulnerabilities
                    risk_rating = 'HIGH'
                    self.report_vulnerability(
                        entry=kb.Entry(
                            title=vulnerability['vulnerability']['title'],
                            risk_rating=risk_rating,
                            short_description=vulnerability['vulnerability']['description'],
                            description=vulnerability['vulnerability']['description'],
                            recommendation='',
                            references={},
                            security_issue=True,
                            privacy_issue=False,
                            has_public_exploit=True,
                            targeted_by_malware=True,
                            targeted_by_ransomware=True,
                            targeted_by_nation_state=True
                        ),
                        technical_detail=f'```json\n{scan_result}\n```',
                        risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH)

        logger.info('done processing the message')


if __name__ == '__main__':
    logger.info('starting agent..')
    AgentTsunami.main()
