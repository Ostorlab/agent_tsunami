"""Unittests for agent."""

from typing import List

from ostorlab.agent.kb import kb
from ostorlab.agent.message import message
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.assets import domain_name as domain_asset
from ostorlab.assets import ipv4 as ipv4_asset
from pytest_mock import plugin

from agent import tsunami_agent as ts_agt
from agent.tsunami.factory import preapre_tagets_tools as tools


def testTsunamiAgent_WhenMessageHaveInvalidIpVersion_ShouldNotCrash(
    tsunami_agent: ts_agt.AgentTsunami,
    agent_mock: List[message.Message],
) -> None:
    """Test Tsunami agent when receiving a message with invalid ip version.
    Tsunami support ipv4, ipv6 and hostname (domain), therefore every received message
    should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """
    msg = message.Message.from_data(
        selector="v3.asset.ip.v4", data={"version": 15631, "host": "0.0.0.0"}
    )

    tsunami_agent.process(msg)

    assert len(agent_mock) == 0


def testTsunamiAgent_WhenTsunamiScanIsCalled_ShouldRaiseValueErrorException(
    mocker: plugin.MockerFixture, tsunami_agent_no_scope: ts_agt.AgentTsunami
) -> None:
    """Test Tsunami agent when receiving a message with invalid ip version.
    Tsunami support ipv4, ipv6 and hostname (domain), therefore every received message
    should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """
    mock_tsunami_scan = mocker.patch(
        "agent.tsunami.tsunami.Tsunami.scan", return_value={"target": 0}
    )
    msg = message.Message.from_data(
        selector="v3.asset.ip.v4", data={"version": 4, "host": "0.0.0.0"}
    )
    target = tools.Target(address="0.0.0.0", version="v4")

    tsunami_agent_no_scope.process(msg)

    mock_tsunami_scan.assert_called_once()
    assert mock_tsunami_scan.call_args.kwargs["target"].address == target.address
    assert mock_tsunami_scan.call_args.kwargs["target"].version == target.version


def testTsunamiAgent_WhenTsunamiScanHasVulnerabilities_ShouldReportVulnerabilities(
    mocker: plugin.MockerFixture, tsunami_agent_no_scope: ts_agt.AgentTsunami
) -> None:
    """Test Tsunami agent when vulnerabilities are detected.
    Tsunami supports ipv4, ipv6 and hostname (domain), therefore every received message
    should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    data = {
        "scanStatus": "SUCCEEDED",
        "vulnerabilities": [
            {
                "vulnerability": {
                    "title": "Ostorlab Platform",
                    "description": "Ostorlab is not password protected",
                    "severity": "CRITICAL",
                    "additionalDetails": [
                        {
                            "textData": {
                                "text": "Vulnerable endpoint: 'http://35.81.162.201/heapdump'"
                            }
                        }
                    ],
                }
            }
        ],
    }
    risk_rating = "CRITICAL"
    description = "Ostorlab is not password protected"
    kb_entry = kb.Entry(
        title="Ostorlab Platform",
        risk_rating=risk_rating,
        short_description=description,
        description=description,
        recommendation="",
        references={},
        security_issue=True,
        privacy_issue=False,
        has_public_exploit=True,
        targeted_by_malware=True,
        targeted_by_ransomware=True,
        targeted_by_nation_state=True,
    )

    mocker.patch("agent.tsunami.tsunami.Tsunami.scan", return_value=data)
    mock_report_vulnerability = mocker.patch(
        "agent.tsunami_agent.AgentTsunami.report_vulnerability", return_value=None
    )
    msg = message.Message.from_data(
        selector="v3.asset.ip.v4", data={"version": 4, "host": "0.0.0.0"}
    )
    tools.Target(address="0.0.0.0", version="v4")

    tsunami_agent_no_scope.process(msg)

    mock_report_vulnerability.assert_called_once_with(
        entry=kb_entry,
        technical_detail="Vulnerable endpoint: 'http://35.81.162.201/heapdump'\n",
        risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
        vulnerability_location=agent_report_vulnerability_mixin.VulnerabilityLocation(
            metadata=[], asset=ipv4_asset.IPv4(host="0.0.0.0", version=4, mask="32")
        ),
        dna='{"endpoint": "Vulnerable endpoint: \'http://35.81.162.201/heapdump\'", "location": {"ipv4": {"host": "0.0.0.0", "mask": "32", "version": 4}, "metadata": []}, "title": "Ostorlab Platform"}',
    )


def testTsunamiAgent_WhenLinkAssetAndTsunamiScanHasVulnerabilities_ShouldReportVulnerabilities(
    mocker: plugin.MockerFixture, tsunami_agent: ts_agt.AgentTsunami
) -> None:
    """Test Tsunami agent when vulnerabilities are detected.
    Tsunami supports ipv4, ipv6 and hostname (domain), therefore every received message
    should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    data = {
        "scanStatus": "SUCCEEDED",
        "vulnerabilities": [
            {
                "vulnerability": {
                    "title": "Ostorlab Platform",
                    "description": "Ostorlab is not password protected",
                    "severity": "HIGH",
                    "additionalDetails": [
                        {
                            "textData": {
                                "text": "Vulnerable endpoint: 'http://35.81.162.201/heapdump'"
                            }
                        }
                    ],
                }
            }
        ],
    }
    risk_rating = "HIGH"
    description = "Ostorlab is not password protected"
    kb_entry = kb.Entry(
        title="Ostorlab Platform",
        risk_rating=risk_rating,
        short_description=description,
        description=description,
        recommendation="",
        references={},
        security_issue=True,
        privacy_issue=False,
        has_public_exploit=True,
        targeted_by_malware=True,
        targeted_by_ransomware=True,
        targeted_by_nation_state=True,
    )

    mocker.patch("agent.tsunami.tsunami.Tsunami.scan", return_value=data)
    mock_report_vulnerability = mocker.patch(
        "agent.tsunami_agent.AgentTsunami.report_vulnerability", return_value=None
    )
    msg = message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "ostorlab.co"}
    )

    tsunami_agent.process(msg)

    mock_report_vulnerability.assert_called_once_with(
        entry=kb_entry,
        technical_detail="Vulnerable endpoint: 'http://35.81.162.201/heapdump'\n",
        risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
        vulnerability_location=agent_report_vulnerability_mixin.VulnerabilityLocation(
            metadata=[
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    agent_report_vulnerability_mixin.MetadataType.URL,
                    "http://ostorlab.co",
                )
            ],
            asset=domain_asset.DomainName(name="ostorlab.co"),
        ),
        dna='{"endpoint": "Vulnerable endpoint: \'http://35.81.162.201/heapdump\'", "location": {"domain_name": {"name": "ostorlab.co"}, "metadata": [{"type": "URL", "value": "http://ostorlab.co"}]}, "title": "Ostorlab Platform"}',
    )


def testTsunamiAgent_WhenServiceAssetAndTsunamiScanHasVulnerabilities_ShouldReportVulnerabilities(
    mocker: plugin.MockerFixture, tsunami_agent: ts_agt.AgentTsunami
) -> None:
    """Test Tsunami agent when vulnerabilities are detected.
    Tsunami supports ipv4, ipv6 and hostname (domain), therefore every received message
    should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    data = {
        "scanStatus": "SUCCEEDED",
        "vulnerabilities": [
            {
                "vulnerability": {
                    "title": "Ostorlab Platform",
                    "description": "Ostorlab is not password protected",
                    "severity": "HIGH",
                    "additionalDetails": [
                        {
                            "textData": {
                                "text": "Vulnerable endpoint: 'http://35.81.162.201/heapdump'"
                            }
                        }
                    ],
                }
            }
        ],
    }
    risk_rating = "HIGH"
    description = "Ostorlab is not password protected"
    kb_entry = kb.Entry(
        title="Ostorlab Platform",
        risk_rating=risk_rating,
        short_description=description,
        description=description,
        recommendation="",
        references={},
        security_issue=True,
        privacy_issue=False,
        has_public_exploit=True,
        targeted_by_malware=True,
        targeted_by_ransomware=True,
        targeted_by_nation_state=True,
    )

    mocker.patch("agent.tsunami.tsunami.Tsunami.scan", return_value=data)
    mock_report_vulnerability = mocker.patch(
        "agent.tsunami_agent.AgentTsunami.report_vulnerability", return_value=None
    )
    msg = message.Message.from_data(
        selector="v3.asset.domain_name.service",
        data={"name": "ostorlab.co", "port": 6000, "schema": "https"},
    )

    tsunami_agent.process(msg)

    mock_report_vulnerability.assert_called_once_with(
        entry=kb_entry,
        technical_detail="Vulnerable endpoint: 'http://35.81.162.201/heapdump'\n",
        risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
        vulnerability_location=agent_report_vulnerability_mixin.VulnerabilityLocation(
            metadata=[
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    agent_report_vulnerability_mixin.MetadataType.PORT, "6000"
                )
            ],
            asset=domain_asset.DomainName(name="ostorlab.co"),
        ),
        dna='{"endpoint": "Vulnerable endpoint: \'http://35.81.162.201/heapdump\'", "location": {"domain_name": {"name": "ostorlab.co"}, "metadata": [{"type": "PORT", "value": "6000"}]}, "title": "Ostorlab Platform"}',
    )


def testTsunamiAgent_WhenDomainNameAssetAndTsunamiScanHasVulnerabilities_ShouldReportVulnerabilities(
    mocker: plugin.MockerFixture, tsunami_agent: ts_agt.AgentTsunami
) -> None:
    """Test Tsunami agent when vulnerabilities are detected.
    Tsunami supports ipv4, ipv6 and hostname (domain), therefore every received message
    should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    data = {
        "scanStatus": "SUCCEEDED",
        "vulnerabilities": [
            {
                "vulnerability": {
                    "title": "Ostorlab Platform",
                    "description": "Ostorlab is not password protected",
                    "severity": "HIGH",
                    "additionalDetails": [
                        {
                            "textData": {
                                "text": "Vulnerable endpoint: 'http://35.81.162.201/heapdump'"
                            }
                        }
                    ],
                }
            }
        ],
    }
    risk_rating = "HIGH"
    description = "Ostorlab is not password protected"
    kb_entry = kb.Entry(
        title="Ostorlab Platform",
        risk_rating=risk_rating,
        short_description=description,
        description=description,
        recommendation="",
        references={},
        security_issue=True,
        privacy_issue=False,
        has_public_exploit=True,
        targeted_by_malware=True,
        targeted_by_ransomware=True,
        targeted_by_nation_state=True,
    )

    mocker.patch("agent.tsunami.tsunami.Tsunami.scan", return_value=data)
    mock_report_vulnerability = mocker.patch(
        "agent.tsunami_agent.AgentTsunami.report_vulnerability", return_value=None
    )
    msg = message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "ostorlab.co"}
    )

    tsunami_agent.process(msg)

    mock_report_vulnerability.assert_called_once_with(
        entry=kb_entry,
        technical_detail="Vulnerable endpoint: 'http://35.81.162.201/heapdump'\n",
        risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
        vulnerability_location=agent_report_vulnerability_mixin.VulnerabilityLocation(
            metadata=[
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    agent_report_vulnerability_mixin.MetadataType.URL,
                    "http://ostorlab.co",
                )
            ],
            asset=domain_asset.DomainName(name="ostorlab.co"),
        ),
        dna='{"endpoint": "Vulnerable endpoint: \'http://35.81.162.201/heapdump\'", "location": {"domain_name": {"name": "ostorlab.co"}, "metadata": [{"type": "URL", "value": "http://ostorlab.co"}]}, "title": "Ostorlab Platform"}',
    )


def testTsunamiAgent_WhenLinkAssetAndTsunamiScanHasVulnerabilities_ShouldNotScan(
    mocker: plugin.MockerFixture, tsunami_agent: ts_agt.AgentTsunami
) -> None:
    """Test Tsunami agent when link doesn't match scop agent regex"""

    _run_command_mock = mocker.patch("subprocess.run", return_value=None)
    msg = message.Message.from_data(
        selector="v3.asset.link", data={"url": "test.ostorlab.co", "method": "GET"}
    )
    tsunami_agent.process(msg)
    _run_command_mock.assert_not_called()


def testTsunamiAgent_WhenDomainNameAssetAndTsunamiScanHasVulnerabilities_ShouldNotScan(
    mocker: plugin.MockerFixture, tsunami_agent: ts_agt.AgentTsunami
) -> None:
    """Test Tsunami agent when domain name doesn't match scop agent regex"""

    _run_command_mock = mocker.patch("subprocess.run", return_value=None)
    msg = message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "https://test.ostorlab.co"}
    )
    tsunami_agent.process(msg)
    _run_command_mock.assert_not_called()


def testTsunamiAgent_WhenMessageIsIpRange_ShouldCallTsunamiForAllHosts(
    mocker: plugin.MockerFixture, tsunami_agent_no_scope: ts_agt.AgentTsunami
) -> None:
    """Test Tsunami agent when receiving a message with ip range.
    should run tsunami on all the hosts in the ip range.
    """
    tsunami_scan_mocker = mocker.patch("agent.tsunami.tsunami.Tsunami.scan")
    msg = message.Message.from_data(
        selector="v3.asset.ip.v4", data={"version": 4, "host": "0.0.0.0", "mask": "28"}
    )
    tsunami_agent_no_scope.process(msg)
    assert tsunami_scan_mocker.call_count == 14


def testAgentTsunami_whenIpRangeScanned_emitsExactIpWhereVulnWasFound(
    ip_small_range_message: message.Message,
    tsunami_agent_no_scope: ts_agt.AgentTsunami,
    agent_mock: List[message.Message],
    mocker: plugin.MockerFixture,
) -> None:
    data = {
        "scanStatus": "SUCCEEDED",
        "vulnerabilities": [
            {
                "vulnerability": {
                    "title": "Ostorlab Platform",
                    "description": "Ostorlab is not password protected",
                    "severity": "HIGH",
                    "additionalDetails": [
                        {
                            "textData": {
                                "text": "Vulnerable endpoint: 'http://35.81.162.201/heapdump'"
                            }
                        }
                    ],
                }
            }
        ],
    }
    mocker.patch("agent.tsunami.tsunami.Tsunami.scan", return_value=data)
    tsunami_agent_no_scope.process(ip_small_range_message)

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert agent_mock[0].data["vulnerability_location"] == {
        "ipv4": {"host": "42.42.42.42", "mask": "32", "version": 4}
    }


def testAgentTsunami_whenIpNoVersion_shouldNotCrash(
    tsunami_agent_no_scope: ts_agt.AgentTsunami,
    agent_mock: List[message.Message],
    mocker: plugin.MockerFixture,
) -> None:
    data = {
        "scanStatus": "SUCCEEDED",
        "vulnerabilities": [
            {
                "vulnerability": {
                    "title": "Ostorlab Platform",
                    "description": "Ostorlab is not password protected",
                    "severity": "HIGH",
                    "additionalDetails": [
                        {
                            "textData": {
                                "text": "Vulnerable endpoint: 'http://35.81.162.201/heapdump'"
                            }
                        }
                    ],
                }
            }
        ],
    }
    mocker.patch("agent.tsunami.tsunami.Tsunami.scan", return_value=data)
    tsunami_agent_no_scope.process(
        message.Message.from_data(
            "v3.asset.ip.v4", data={"host": "34.141.29.206", "mask": "32"}
        )
    )

    assert "v3.report.vulnerability" in [a.selector for a in agent_mock]
    assert agent_mock[0].data["vulnerability_location"] == {
        "ipv4": {"host": "34.141.29.206", "mask": "32", "version": 4}
    }


def testAgentTsunami_whenIpNoTValid_shouldRaiseValueError(
    tsunami_agent_no_scope: ts_agt.AgentTsunami,
    agent_mock: List[message.Message],
) -> None:
    invalid_ip = message.Message.from_data(
        "v3.asset.ip.v4", data={"host": "34.141.29", "mask": "32"}
    )

    tsunami_agent_no_scope.process(invalid_ip)

    assert len(agent_mock) == 0


def testTsunamiAgent_WhenDomainNameAssetAndTsunamiScanHasCredVulnerabilities_shouldReportVulnerabilities(
    mocker: plugin.MockerFixture, tsunami_agent: ts_agt.AgentTsunami
) -> None:
    """Test Tsunami agent when vulnerabilities are detected.
    Tsunami supports ipv4, ipv6 and hostname (domain), therefore every received message
    should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    data = {
        "scanStatus": "SUCCEEDED",
        "vulnerabilities": [
            {
                "vulnerability": {
                    "title": "Ostorlab Platform",
                    "description": "Ostorlab is not password protected",
                    "severity": "HIGH",
                    "additionalDetails": [
                        {"credential": {"username": "user", "password": "password"}}
                    ],
                }
            }
        ],
    }
    risk_rating = "HIGH"
    description = "Ostorlab is not password protected"
    kb_entry = kb.Entry(
        title="Ostorlab Platform",
        risk_rating=risk_rating,
        short_description=description,
        description=description,
        recommendation="",
        references={},
        security_issue=True,
        privacy_issue=False,
        has_public_exploit=True,
        targeted_by_malware=True,
        targeted_by_ransomware=True,
        targeted_by_nation_state=True,
    )

    mocker.patch("agent.tsunami.tsunami.Tsunami.scan", return_value=data)
    mock_report_vulnerability = mocker.patch(
        "agent.tsunami_agent.AgentTsunami.report_vulnerability", return_value=None
    )
    msg = message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "ostorlab.co"}
    )

    tsunami_agent.process(msg)

    mock_report_vulnerability.assert_called_once_with(
        entry=kb_entry,
        technical_detail="The extracted credential for the vulnerable network service: user:password \n",
        risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
        vulnerability_location=agent_report_vulnerability_mixin.VulnerabilityLocation(
            metadata=[
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    agent_report_vulnerability_mixin.MetadataType.URL,
                    "http://ostorlab.co",
                )
            ],
            asset=domain_asset.DomainName(name="ostorlab.co"),
        ),
        dna='{"credentials": ["user:password"], "location": {"domain_name": {"name": "ostorlab.co"}, "metadata": [{"type": "URL", "value": "http://ostorlab.co"}]}, "title": "Ostorlab Platform"}',
    )


def testTsunamiAgent_whenDomainNameAssetAndTsunamiScanHasCredsVulnerabilities_shouldReportVulnerabilities(
    mocker: plugin.MockerFixture, tsunami_agent: ts_agt.AgentTsunami
) -> None:
    """Test Tsunami agent when vulnerabilities are detected.
    Tsunami supports ipv4, ipv6 and hostname (domain), therefore every received message
    should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    data = {
        "scanStatus": "SUCCEEDED",
        "vulnerabilities": [
            {
                "vulnerability": {
                    "title": "Ostorlab Platform",
                    "description": "Ostorlab is not password protected",
                    "severity": "HIGH",
                    "additionalDetails": [
                        {"credentials": [{"username": "user", "password": "password"}]}
                    ],
                }
            }
        ],
    }
    risk_rating = "HIGH"
    description = "Ostorlab is not password protected"
    kb_entry = kb.Entry(
        title="Ostorlab Platform",
        risk_rating=risk_rating,
        short_description=description,
        description=description,
        recommendation="",
        references={},
        security_issue=True,
        privacy_issue=False,
        has_public_exploit=True,
        targeted_by_malware=True,
        targeted_by_ransomware=True,
        targeted_by_nation_state=True,
    )

    mocker.patch("agent.tsunami.tsunami.Tsunami.scan", return_value=data)
    mock_report_vulnerability = mocker.patch(
        "agent.tsunami_agent.AgentTsunami.report_vulnerability", return_value=None
    )
    msg = message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "ostorlab.co"}
    )

    tsunami_agent.process(msg)

    mock_report_vulnerability.assert_called_once_with(
        entry=kb_entry,
        technical_detail="The extracted credential for the vulnerable network service: user:password \n",
        risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
        vulnerability_location=agent_report_vulnerability_mixin.VulnerabilityLocation(
            metadata=[
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    agent_report_vulnerability_mixin.MetadataType.URL,
                    "http://ostorlab.co",
                )
            ],
            asset=domain_asset.DomainName(name="ostorlab.co"),
        ),
        dna='{"credentials": ["user:password"], "location": {"domain_name": {"name": "ostorlab.co"}, "metadata": [{"type": "URL", "value": "http://ostorlab.co"}]}, "title": "Ostorlab Platform"}',
    )
