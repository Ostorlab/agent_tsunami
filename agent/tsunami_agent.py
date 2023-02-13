"""Agent implementation for tsunami scanner."""
import ipaddress
import logging
import re
import urllib
from typing import Any, Optional, Tuple
from urllib import parse

from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.assets import domain_name as domain_asset
from ostorlab.assets import ipv4 as ipv4_asset
from ostorlab.assets import ipv6 as ipv6_asset
from ostorlab.assets import link as link_asset
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent.tsunami import tsunami

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level="INFO",
    force=True,
)
logger = logging.getLogger(__name__)


class AgentTsunami(
    agent.Agent,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
    persist_mixin.AgentPersistMixin,
):
    """Tsunami scanner implementation for ostorlab. using ostorlab python sdk.
    For more visit https://github.com/Ostorlab/ostorlab."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        super().__init__(agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self._scope_urls_regex: Optional[str] = self.args.get("scope_urls_regex")

    def _check_asset_was_added(self, targets: tsunami.Target) -> bool:
        """Check if the asset was scanned before or not"""
        if targets.domain is not None:
            if self.set_add(b"agent_tsunami", f"{targets.domain}"):
                logger.info("target %s/ was processed before, exiting", targets.domain)
                return False
        return True

    def _get_vuln_location(
        self, target: tsunami.Target
    ) -> agent_report_vulnerability_mixin.VulnerabilityLocation:
        """get the vulnerability location representation of the target
        Args:
            target: domaine-name or ipv4 or ipv6
        """
        metadata = []
        asset: ipv4_asset.IPv4 | ipv6_asset.IPv6 | link_asset.Link | domain_asset.DomainName
        if target.address is not None:
            if target.version == "v4":
                asset = ipv4_asset.IPv4(host=target.address, version=4, mask="32")
            else:
                asset = ipv6_asset.IPv6(host=target.address, version=6, mask="128")

        elif target.domain is not None:
            url = urllib.parse.urlparse(target.domain)
            assert url.hostname is not None
            if url.port is not None:
                metadata_type = agent_report_vulnerability_mixin.MetadataType.PORT
                metadata_value = str(url.port)
                asset = domain_asset.DomainName(name=url.hostname)

            else:
                metadata_type = agent_report_vulnerability_mixin.MetadataType.URL
                metadata_value = target.domain
                asset = domain_asset.DomainName(name=url.hostname)

            metadata = [
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    metadata_type=metadata_type, value=metadata_value
                )
            ]

        return agent_report_vulnerability_mixin.VulnerabilityLocation(
            asset=asset, metadata=metadata
        )

    def process(self, message: msg.Message) -> None:
        """Starts a tsunami scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime."""

        logger.info("processing message of selector : %s", message.selector)
        if message.data.get("host") is not None:
            host = message.data.get("host")
            mask = message.data.get("mask")
            if mask is not None:
                addresses = ipaddress.ip_network(f"{host}/{mask}")
            else:
                addresses = ipaddress.ip_network(f"{host}")
            if not self.add_ip_network("agent_tsunami", addresses):
                logger.info("target %s was processed before, exiting", addresses)
                return

        targets, t = self._prepare_targets(message=message)

        if self._should_process_target(self._scope_urls_regex, t) is True:
            for target in targets:
                if target.domain is not None:
                    if self._check_asset_was_added(target) is True:
                        return
                with tsunami.Tsunami() as tsunami_scanner:
                    vuln_location = self._get_vuln_location(target)

                    scan_result = tsunami_scanner.scan(target=target)
                    logger.info(
                        "found %d vulnerabilities",
                        len(scan_result.get("vulnerabilities", [])),
                    )
                    for vulnerability in scan_result.get("vulnerabilities", {}):
                        # risk_rating will be HIGH for all detected vulnerabilities
                        risk_rating = "HIGH"
                        self.report_vulnerability(
                            entry=kb.Entry(
                                title=vulnerability["vulnerability"]["title"],
                                risk_rating=risk_rating,
                                short_description=vulnerability["vulnerability"][
                                    "description"
                                ],
                                description=vulnerability["vulnerability"][
                                    "description"
                                ],
                                recommendation="",
                                references={},
                                security_issue=True,
                                privacy_issue=False,
                                has_public_exploit=True,
                                targeted_by_malware=True,
                                targeted_by_ransomware=True,
                                targeted_by_nation_state=True,
                            ),
                            technical_detail=f"```json\n{scan_result}\n```",
                            risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                            vulnerability_location=vuln_location,
                        )

        logger.info("done processing the message")

    def _should_process_target(self, scope_urls_regex: Optional[str], url: str) -> bool:
        if scope_urls_regex is None:
            return True
        link_in_scan_domain = re.match(scope_urls_regex, url) is not None
        if not link_in_scan_domain:
            logger.warning("link url %s is not in domain %s", url, scope_urls_regex)
        return link_in_scan_domain

    def _get_schema(self, message: msg.Message) -> str:
        """Returns the schema to be used for the target."""
        if message.data.get("schema") is not None:
            return str(message.data["schema"])
        elif message.data.get("protocol") is not None:
            return str(message.data["protocol"])
        elif self.args.get("https") is True:
            return "https"
        else:
            return "http"

    def _prepare_targets(self, message: msg.Message) -> Tuple[Any, Any]:
        """Prepare Targets and dispatch it to prepare: domain/link and hosts."""
        # domain_name message
        if message.data.get("name") is not None:
            target = str(message.data["name"])
            schema = self._get_schema(message)
            port = message.data.get("port")
            if schema == "https" and port not in [443, None]:
                url = f"https://{target}:{port}"
            elif schema == "https":
                url = f"https://{target}"
            elif port == 80:
                url = f"http://{target}"
            elif port is None:
                url = f"{schema}://{target}"
            else:
                url = f"{schema}://{target}:{port}"
            return [tsunami.Target(domain=url)], url
        # link message
        elif message.data.get("url") is not None:
            target = str(message.data["url"])
            return [tsunami.Target(domain=str(parse.urlparse(target).netloc))], target
        # IP message
        elif message.data.get("host") is not None:
            version = message.data["version"]
            if version == 6:
                version = "v6"
            elif message.data["version"] == 4:
                version = "v4"
            else:
                raise ValueError(f'Incorrect ip version {message.data["version"]}')
            try:
                if message.data.get("mask") is None:
                    ip_network = ipaddress.ip_network(message.data["host"])
                else:
                    ip_network = ipaddress.ip_network(
                        f"""{message.data.get('host')}/{message.data.get('mask')}"""
                    )
                return [
                    tsunami.Target(version=version, address=str(host))
                    for host in ip_network.hosts()
                ], ip_network
            except ValueError:
                logger.info(
                    "Incorrect %s / %s",
                    {message.data.get("host")},
                    {message.data.get("mask")},
                )
                return [], None

        return [], None


if __name__ == "__main__":
    logger.info("starting agent..")
    AgentTsunami.main()
