"""Unittests for agent."""

import pytest
from ostorlab.agent import message
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin

from agent.tsunami import tsunami


def testTsunamiAgent_WhenMessageHaveInvalidIpVersion_ShouldRaiseValueErrorException(tsunami_agent):
    """Test Tsunami agent when receiving a message with invalid ip version.
        Tsunami support ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 15631, 'host': '0.0.0.0'})

    with pytest.raises(ValueError):
        tsunami_agent.process(msg)


def testTsunamiAgent_WhenTsunamiScanIsCalled_ShouldRaiseValueErrorException(mocker, tsunami_agent):
    """Test Tsunami agent when receiving a message with invalid ip version.
        Tsunami support ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """
    mock_tsunami_scan = mocker.patch('agent.tsunami.tsunami.Tsunami.scan', return_value={'target': 0})
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '0.0.0.0'})
    target = tsunami.Target(address='0.0.0.0', version='v4')

    tsunami_agent.process(msg)

    mock_tsunami_scan.assert_called_once()
    assert mock_tsunami_scan.call_args.kwargs['target'].address == target.address
    assert mock_tsunami_scan.call_args.kwargs['target'].version == target.version


def testTsunamiAgent_WhenTsunamiScanHasVulnerabilities_ShouldReportVulnerabilities(mocker, tsunami_agent):
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
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '0.0.0.0'})
    tsunami.Target(address='0.0.0.0', version='v4')

    tsunami_agent.process(msg)

    mock_report_vulnerability.assert_called_once_with(entry=kb_entry,
                                                      technical_detail=f'```json\n{data}\n```',
                                                      risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH)


def testTsunamiAgent_WhenLinkAssetAndTsunamiScanHasVulnerabilities_ShouldReportVulnerabilities(mocker, tsunami_agent):
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
    msg = message.Message.from_data(selector='v3.asset.link', data={'url': 'https://test.ostorlab.co',
                                                                    'method': 'GET'})
    tsunami.Target(domain='test.ostorlab.co')

    tsunami_agent.process(msg)

    mock_report_vulnerability.assert_called_once_with(entry=kb_entry,
                                                      technical_detail=f'```json\n{data}\n```',
                                                      risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH)


def testTsunamiAgent_WhenMessageIsIpRange_ShouldCallTsunamiForAllHosts(tsunami_agent, mocker):
    """Test Tsunami agent when receiving a message with ip range.
        should run tsunami on all the hosts in the ip range.
    """
    tsunami_scan_mocker = mocker.patch('agent.tsunami.tsunami.Tsunami.scan')
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '0.0.0.0', 'mask': '28'})
    tsunami_agent.process(msg)
    assert tsunami_scan_mocker.call_count == 14


def testTsunamiAgent_WhenMessageIsInvalidIpAddress_ShouldRaiseError(tsunami_agent, mocker):
    """Test Tsunami agent when receiving a message with invalid ip.
        Tsunami support ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip, other-ways the agent should raise a ValueError exception.
    """
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '0.0.0.0.4', 'mask': '32'})
    with pytest.raises(ValueError):
        tsunami_agent.process(msg)
