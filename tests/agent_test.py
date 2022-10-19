"""Unittests for agent."""

import pytest
from typing import List

from ostorlab.agent.message import message
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from pytest_mock import plugin
from agent.tsunami import tsunami
from agent import tsunami_agent as ts_agt
from ostorlab.assets import ipv4 as ipv4_asset
from ostorlab.assets import domain_name as domain_asset
from ostorlab.assets import link as link_asset


def testTsunamiAgent_WhenMessageHaveInvalidIpVersion_ShouldRaiseValueErrorException(
        tsunami_agent: ts_agt.AgentTsunami) -> None:
    """Test Tsunami agent when receiving a message with invalid ip version.
        Tsunami support ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 15631, 'host': '0.0.0.0'})

    with pytest.raises(ValueError):
        tsunami_agent.process(msg)


def testTsunamiAgent_WhenTsunamiScanIsCalled_ShouldRaiseValueErrorException(mocker: plugin.MockerFixture,
                                                                            tsunami_agent_no_scope:
                                                                            ts_agt.AgentTsunami) -> None:
    """Test Tsunami agent when receiving a message with invalid ip version.
        Tsunami support ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """
    mock_tsunami_scan = mocker.patch('agent.tsunami.tsunami.Tsunami.scan', return_value={'target': 0})
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '0.0.0.0'})
    target = tsunami.Target(address='0.0.0.0', version='v4')

    tsunami_agent_no_scope.process(msg)

    mock_tsunami_scan.assert_called_once()
    assert mock_tsunami_scan.call_args.kwargs['target'].address == target.address
    assert mock_tsunami_scan.call_args.kwargs['target'].version == target.version


def testTsunamiAgent_WhenTsunamiScanHasVulnerabilities_ShouldReportVulnerabilities(
        mocker: plugin.MockerFixture,
        tsunami_agent_no_scope: ts_agt.AgentTsunami) -> None:
    """Test Tsunami agent when vulnerabilities are detected.
        Tsunami supports ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    data = {
        'scanStatus': 'SUCCEEDED',
        'vulnerabilities': [
            {
                'vulnerability': {
                    'title': 'Ostorlab Platform',
                    'description': 'Ostorlab is not password protected'
                }
            }
        ]
    }
    risk_rating = 'HIGH'
    description = 'Ostorlab is not password protected'
    kb_entry = kb.Entry(
        title='Ostorlab Platform',
        risk_rating=risk_rating,
        short_description=description,
        description=description,
        recommendation='',
        references={},
        security_issue=True,
        privacy_issue=False,
        has_public_exploit=True,
        targeted_by_malware=True,
        targeted_by_ransomware=True,
        targeted_by_nation_state=True,
    )

    mocker.patch('agent.tsunami.tsunami.Tsunami.scan', return_value=data)
    mock_report_vulnerability = mocker.patch('agent.tsunami_agent.AgentTsunami.report_vulnerability', return_value=None)
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '0.0.0.0'})
    tsunami.Target(address='0.0.0.0', version='v4')

    tsunami_agent_no_scope.process(msg)

    mock_report_vulnerability.assert_called_once_with(entry=kb_entry,
                                                      technical_detail=f'```json\n{data}\n```',
                                                      risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                                                      vulnerability_location=agent_report_vulnerability_mixin.VulnerabilityLocation(metadata=[],
                                                                                                                                    asset=ipv4_asset.IPv4(host='0.0.0.0', version=4, mask='32')
                                                                                                                                    ))



def testTsunamiAgent_WhenLinkAssetAndTsunamiScanHasVulnerabilities_ShouldReportVulnerabilities(
        mocker: plugin.MockerFixture,
        tsunami_agent: ts_agt.AgentTsunami) -> None:
    """Test Tsunami agent when vulnerabilities are detected.
        Tsunami supports ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    data = {
        'scanStatus': 'SUCCEEDED',
        'vulnerabilities': [
            {
                'vulnerability': {
                    'title': 'Ostorlab Platform',
                    'description': 'Ostorlab is not password protected'
                }
            }
        ]
    }
    risk_rating = 'HIGH'
    description = 'Ostorlab is not password protected'
    kb_entry = kb.Entry(
        title='Ostorlab Platform',
        risk_rating=risk_rating,
        short_description=description,
        description=description,
        recommendation='',
        references={},
        security_issue=True,
        privacy_issue=False,
        has_public_exploit=True,
        targeted_by_malware=True,
        targeted_by_ransomware=True,
        targeted_by_nation_state=True
    )

    mocker.patch('agent.tsunami.tsunami.Tsunami.scan', return_value=data)
    mock_report_vulnerability = mocker.patch('agent.tsunami_agent.AgentTsunami.report_vulnerability', return_value=None)
    msg = message.Message.from_data(selector='v3.asset.link', data={'url': 'https://ostorlab.co',
                                                                    'method': 'GET'})

    tsunami_agent.process(msg)

    mock_report_vulnerability.assert_called_once_with(entry=kb_entry,
                                                      technical_detail=f'```json\n{data}\n```',
                                                      risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                                                      vulnerability_location=agent_report_vulnerability_mixin.VulnerabilityLocation(
                                                          metadata=[],
                                                          asset=domain_asset.DomainName(name='https://ostorlab.co')
                                                          )
                                                      )

def testTsunamiAgent_WhenServiceAssetAndTsunamiScanHasVulnerabilities_ShouldReportVulnerabilities(
        mocker: plugin.MockerFixture,
        tsunami_agent: ts_agt.AgentTsunami) -> None:
    """Test Tsunami agent when vulnerabilities are detected.
        Tsunami supports ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    data = {
        'scanStatus': 'SUCCEEDED',
        'vulnerabilities': [
            {
                'vulnerability': {
                    'title': 'Ostorlab Platform',
                    'description': 'Ostorlab is not password protected'
                }
            }
        ]
    }
    risk_rating = 'HIGH'
    description = 'Ostorlab is not password protected'
    kb_entry = kb.Entry(
        title='Ostorlab Platform',
        risk_rating=risk_rating,
        short_description=description,
        description=description,
        recommendation='',
        references={},
        security_issue=True,
        privacy_issue=False,
        has_public_exploit=True,
        targeted_by_malware=True,
        targeted_by_ransomware=True,
        targeted_by_nation_state=True
    )

    mocker.patch('agent.tsunami.tsunami.Tsunami.scan', return_value=data)
    mock_report_vulnerability = mocker.patch('agent.tsunami_agent.AgentTsunami.report_vulnerability', return_value=None)
    msg = message.Message.from_data(selector='v3.asset.domain_name.service', data={'name': 'ostorlab.co',
                                                                                   'port': 6000,
                                                                                   'schema': 'https'
                                                                                   })

    tsunami_agent.process(msg)

    mock_report_vulnerability.assert_called_once_with(entry=kb_entry,
                                                      technical_detail=f'```json\n{data}\n```',
                                                      risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                                                      vulnerability_location=agent_report_vulnerability_mixin.VulnerabilityLocation(
                                                          metadata=[agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(agent_report_vulnerability_mixin.MetadataType.PORT, '6000')],
                                                          asset=link_asset.Link(url='https://ostorlab.co', method='GET')
                                                          )
                                                      )


def testTsunamiAgent_WhenDomainNameAssetAndTsunamiScanHasVulnerabilities_ShouldReportVulnerabilities(
        mocker: plugin.MockerFixture,
        tsunami_agent: ts_agt.AgentTsunami) -> None:
    """Test Tsunami agent when vulnerabilities are detected.
        Tsunami supports ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    data = {
        'scanStatus': 'SUCCEEDED',
        'vulnerabilities': [
            {
                'vulnerability': {
                    'title': 'Ostorlab Platform',
                    'description': 'Ostorlab is not password protected'
                }
            }
        ]
    }
    risk_rating = 'HIGH'
    description = 'Ostorlab is not password protected'
    kb_entry = kb.Entry(
        title='Ostorlab Platform',
        risk_rating=risk_rating,
        short_description=description,
        description=description,
        recommendation='',
        references={},
        security_issue=True,
        privacy_issue=False,
        has_public_exploit=True,
        targeted_by_malware=True,
        targeted_by_ransomware=True,
        targeted_by_nation_state=True
    )

    mocker.patch('agent.tsunami.tsunami.Tsunami.scan', return_value=data)
    mock_report_vulnerability = mocker.patch('agent.tsunami_agent.AgentTsunami.report_vulnerability', return_value=None)
    msg = message.Message.from_data(selector='v3.asset.domain_name', data={'name': 'ostorlab.co'})

    tsunami_agent.process(msg)

    mock_report_vulnerability.assert_called_once_with(entry=kb_entry,
                                                      technical_detail=f'```json\n{data}\n```',
                                                      risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                                                      vulnerability_location=agent_report_vulnerability_mixin.VulnerabilityLocation(
                                                          metadata=[],
                                                          asset=link_asset.Link(url='http://ostorlab.co', method='GET')
                                                        )
                                                      )


def testTsunamiAgent_WhenLinkAssetAndTsunamiScanHasVulnerabilities_ShouldNotScan(
        mocker: plugin.MockerFixture,
        tsunami_agent: ts_agt.AgentTsunami) -> None:
    """Test Tsunami agent when link doesn't match scop agent regex
    """

    _run_command_mock = mocker.patch('subprocess.run', return_value=None)
    msg = message.Message.from_data(selector='v3.asset.link', data={'url': 'test.ostorlab.co',
                                                                    'method': 'GET'})
    tsunami_agent.process(msg)
    _run_command_mock.assert_not_called()


def testTsunamiAgent_WhenDomainNameAssetAndTsunamiScanHasVulnerabilities_ShouldNotScan(
        mocker: plugin.MockerFixture,
        tsunami_agent: ts_agt.AgentTsunami) -> None:
    """Test Tsunami agent when domain name doesn't match scop agent regex
    """

    _run_command_mock = mocker.patch('subprocess.run', return_value=None)
    msg = message.Message.from_data(selector='v3.asset.domain_name', data={'name': 'https://test.ostorlab.co'})
    tsunami_agent.process(msg)
    _run_command_mock.assert_not_called()


def testTsunamiAgent_WhenMessageIsIpRange_ShouldCallTsunamiForAllHosts(mocker: plugin.MockerFixture,
                                                                       tsunami_agent_no_scope:
                                                                       ts_agt.AgentTsunami) -> None:
    """Test Tsunami agent when receiving a message with ip range.
        should run tsunami on all the hosts in the ip range.
    """
    tsunami_scan_mocker = mocker.patch('agent.tsunami.tsunami.Tsunami.scan')
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '0.0.0.0', 'mask': '28'})
    tsunami_agent_no_scope.process(msg)
    assert tsunami_scan_mocker.call_count == 14


def testAgentTsunami_whenIpRangeScanned_emitsExactIpWhereVulnWasFound(
    ip_small_range_message: message.Message,
    tsunami_agent_no_scope: ts_agt.AgentTsunami,
    agent_mock: List[message.Message],
    mocker: plugin.MockerFixture
) -> None:
    data = {
        'scanStatus': 'SUCCEEDED',
        'vulnerabilities': [
            {
                'vulnerability': {
                    'title': 'Ostorlab Platform',
                    'description': 'Ostorlab is not password protected'
                }
            }
        ]
    }
    mocker.patch('agent.tsunami.tsunami.Tsunami.scan', return_value=data)
    tsunami_agent_no_scope.process(ip_small_range_message)

    assert 'v3.report.vulnerability' in [a.selector for a in agent_mock]
    assert ['ipv4'] in [list(a.data.get('vulnerability_location', {}).keys()) for a in agent_mock]
