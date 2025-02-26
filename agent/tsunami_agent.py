"""Agent implementation for tsunami scanner."""

import ipaddress
import json
import logging
import re
import urllib
from typing import Optional, Any

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

from agent import vpn
from agent.tsunami import tsunami
from agent.tsunami.factory import preapre_tagets_tools as tools

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level="INFO",
    force=True,
)
logger = logging.getLogger(__name__)

# severity mapping defined in https://github.com/google/tsunami-security-scanner/blob/master/proto/vulnerability.proto
RISK_MAPPING = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "MINIMAL": "INFO",
    "SEVERITY_UNSPECIFIED": "POTENTIALLY",
}


class AgentTsunami(
    agent.Agent,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
    persist_mixin.AgentPersistMixin,
):
    """Tsunami scanner implementation for ostorlab. using ostorlab python sdk.
    For more visit https://github.com/Ostorlab/ostorlab."""

    def start(self) -> None:
        if self._vpn_config is not None and self._dns_config is not None:
            vpn.enable_vpn(vpn_config=self._vpn_config, dns_config=self._dns_config)

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        super().__init__(agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self._scope_urls_regex: Optional[str] = self.args.get("scope_urls_regex")
        self._vpn_config = self.args.get("vpn_config")
        self._dns_config = self.args.get("dns_config")

    def process(self, message: msg.Message) -> None:
        """Starts a tsunami scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime."""

        logger.debug("processing message of selector : %s", message.selector)

        logger.info("Preparing targets ...")
        targets = tools.prepare_targets(message=message, args=self.args)
        if targets is None or len(targets) == 0:
            logger.info("Invalid target message %s", message)
            return
        if self._should_process_target(message=message, target=targets[0]) is True:
            logger.info("Scanning targets `%s`.", targets)
            for target in targets:
                if target.domain is not None:
                    if self._check_asset_was_added(target) is True:
                        return
                with tsunami.Tsunami() as tsunami_scanner:
                    vuln_location = self._get_vuln_location(target)

                    scan_result = tsunami_scanner.scan(target=target)
                    logger.info(
                        "Found %d vulnerabilities.",
                        len(scan_result.get("vulnerabilities", [])),
                    )
                    for vulnerability in scan_result.get("vulnerabilities", {}):
                        self._report_vulnerability(vulnerability, vuln_location)

        logger.info("Done scanning targets.")

    def _check_asset_was_added(self, targets: tools.Target) -> bool:
        """Check if the asset was scanned before or not"""
        if targets.domain is not None:
            if self.set_add(b"agent_tsunami", f"{targets.domain}"):
                logger.debug("target %s/ was processed before, exiting", targets.domain)
                return False
        return True

    def _should_process_target(
        self, message: msg.Message, target: tools.Target
    ) -> bool:
        if message.data.get("name") is not None or message.data.get("url") is not None:
            return self._should_process_url_targets(target=target.url)
        elif message.data.get("host") is not None:
            return self._should_process_ip_targets(message=message)
        return True

    def _should_process_url_targets(self, target: Optional[str]) -> bool:
        if target is None:
            return False

        if self._scope_urls_regex is None:
            return True

        if re.match(self._scope_urls_regex, target) is None:
            logger.warning(
                "link url %s is not in domain %s", target, self._scope_urls_regex
            )
            return False
        else:
            return True

    def _should_process_ip_targets(self, message: msg.Message) -> bool:
        host = message.data.get("host")
        mask = message.data.get("mask")
        if mask is not None:
            addresses = ipaddress.ip_network(f"{host}/{mask}")
        else:
            addresses = ipaddress.ip_network(f"{host}")
        if self.add_ip_network("agent_tsunami", addresses) is False:
            logger.debug("target %s was processed before, exiting", addresses)
            return False
        return True

    def _get_vuln_location(
        self, target: tools.Target
    ) -> agent_report_vulnerability_mixin.VulnerabilityLocation:
        """get the vulnerability location representation of the target
        Args:
            target: domaine-name or ipv4 or ipv6
        """
        metadata = []
        asset: (
            ipv4_asset.IPv4
            | ipv6_asset.IPv6
            | link_asset.Link
            | domain_asset.DomainName
        )
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

    def _report_vulnerability(
        self,
        vulnerability: dict[str, dict[str, Any]],
        vuln_location: agent_report_vulnerability_mixin.VulnerabilityLocation,
    ) -> None:
        risk_rating = RISK_MAPPING[vulnerability["vulnerability"]["severity"]]
        technical_detail = self._format_technical_detail(vulnerability["vulnerability"])
        self.report_vulnerability(
            entry=kb.Entry(
                title=vulnerability["vulnerability"]["title"],
                risk_rating=risk_rating,
                short_description=vulnerability["vulnerability"]["description"],
                description=vulnerability["vulnerability"]["description"],
                recommendation="",
                references={},
                security_issue=True,
                privacy_issue=False,
                has_public_exploit=True,
                targeted_by_malware=True,
                targeted_by_ransomware=True,
                targeted_by_nation_state=True,
            ),
            technical_detail=technical_detail,
            risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
            vulnerability_location=vuln_location,
            dna=_compute_dna(
                vuln_title=vulnerability["vulnerability"]["title"],
                vuln_location=vuln_location,
                details=self._get_credentials(vulnerability["vulnerability"]),
            ),
        )

    def _format_technical_detail(self, vulnerability: dict[str, Any]) -> str:
        technical_detail = ""
        additional_details = vulnerability.get("additionalDetails", [])
        for additional_detail in additional_details:
            if "textData" in additional_detail:
                technical_detail += f"{additional_detail['textData']['text']}\n"
            elif "credential" in additional_detail:
                technical_detail += (
                    f"The extracted credential for the vulnerable network service:"
                    f" {additional_detail['credential']['username']}:{additional_detail['credential']['password']} \n"
                )
            elif "credentials" in additional_detail:
                for credential in additional_detail["credentials"]:
                    technical_detail += (
                        f"The extracted credential for the vulnerable network service:"
                        f" {credential['username']}:{credential['password']} \n"
                    )
        if technical_detail == "":
            technical_detail = f"```json\n{additional_details}\n```"

        return technical_detail

    def _get_credentials(self, vulnerability: dict[str, Any]) -> dict[str, Any]:
        additional_details = vulnerability.get("additionalDetails", [])
        credentials = []
        for additional_detail in additional_details:
            if "textData" in additional_detail:
                return {"endpoint": additional_detail.get("textData", {}).get("text")}
            elif "credential" in additional_detail:
                credentials.append(
                    f"{additional_detail.get('credential', {}).get('username')}:{additional_detail.get('credential', {}).get('password')}"
                )
            elif "credentials" in additional_detail:
                for credential in additional_detail.get("credentials"):
                    credentials.append(
                        f"{credential.get('username')}:{credential.get('password')}"
                    )

        return {"credentials": credentials}


def _compute_dna(
    vuln_title: str,
    vuln_location: agent_report_vulnerability_mixin.VulnerabilityLocation | None,
    details: dict[str, Any] | None,
) -> str:
    """Compute a deterministic, debuggable DNA representation for a vulnerability.
    Args:
        vuln_title: The title of the vulnerability.
        vuln_location: The location of the vulnerability.
        details: The tsunami result details.
    Returns:
        A deterministic JSON representation of the vulnerability DNA.
    """
    dna_data: dict[str, Any] = {"title": vuln_title}

    if vuln_location is not None:
        location_dict: dict[str, Any] = vuln_location.to_dict()
        sorted_location_dict = _sort_dict(location_dict)
        dna_data["location"] = sorted_location_dict

    if details is not None:
        dna_data.update(details)

    return json.dumps(dna_data, sort_keys=True)


def _sort_dict(d: dict[str, Any] | list[Any]) -> dict[str, Any] | list[Any]:
    """Recursively sort dictionary keys and lists within.
    Args:
        d: The dictionary or list to sort.
    Returns:
        A sorted dictionary or list.
    """
    if isinstance(d, dict):
        return {k: _sort_dict(v) for k, v in sorted(d.items())}
    if isinstance(d, list):
        return sorted(
            d,
            key=lambda x: json.dumps(x, sort_keys=True)
            if isinstance(x, dict)
            else str(x),
        )
    return d


if __name__ == "__main__":
    logger.info("starting agent..")
    AgentTsunami.main()
