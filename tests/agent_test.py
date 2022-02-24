"""Unittests for agent."""

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin

from agent import tsunami_agent
from agent.tsunami import tsunami


def testTsunamiAgent_WhenMessageHaveInvalidIpVersion_ShouldRaiseValueErrorException():
    """Test Tsunami agent when receiving a message with invalid ip version.
        Tsunami support ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """
    # providing invalid version
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 15631, 'host': '0.0.0.0'})
    definition = agent_definitions.AgentDefinition(name='start_test_agent', out_selectors=['v3.report.vulnerability'])
    settings = runtime_definitions.AgentSettings(key='agent/ostorlab/tsunami_agent')
    test_agent = tsunami_agent.AgentTsunami(definition, settings)

    with pytest.raises(ValueError):
        test_agent.process(msg)


def testTsunamiAgent_WhenTsunamiScanIsCalled_ShouldRaiseValueErrorException(mocker):
    """Test Tsunami agent when receiving a message with invalid ip version.
        Tsunami support ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    mock_tsunami_scan = mocker.patch('agent.tsunami.tsunami.Tsunami.scan', return_value={'target': 0})
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '0.0.0.0'})
    definition = agent_definitions.AgentDefinition(name='start_test_agent', out_selectors=['v3.report.vulnerability'])
    settings = runtime_definitions.AgentSettings(key='agent/ostorlab/tsunami_agent')
    target = tsunami.Target(address='0.0.0.0', version='v4')
    test_agent = tsunami_agent.AgentTsunami(definition, settings)

    test_agent.process(msg)

    mock_tsunami_scan.assert_called_once()
    assert mock_tsunami_scan.call_args.kwargs['target'].address == target.address
    assert mock_tsunami_scan.call_args.kwargs['target'].version == target.version


def testTsunamiAgent_WhenTsunamiScanHasVulnerabilities_ShouldReportVulnerabilities(mocker):
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
    kb_entry =  kb.Entry(
                        title='Ostorlab Platform',
                        risk_rating=risk_rating,
                        short_description=description,
                        description=description,
                        recommendation = '',
                        references = {},
                        security_issue = True,
                        privacy_issue = False,
                        has_public_exploit = True,
                        targeted_by_malware = True,
                        targeted_by_ransomware = True,
                        targeted_by_nation_state = True
                    )

    mocker.patch('agent.tsunami.tsunami.Tsunami.scan', return_value=data)
    mock_report_vulnerability = mocker.patch('agent.tsunami_agent.AgentTsunami.report_vulnerability', return_value=None)

    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '0.0.0.0'})
    definition = agent_definitions.AgentDefinition(name='start_test_agent', out_selectors=['v3.report.vulnerability'])
    settings = runtime_definitions.AgentSettings(key='agent/ostorlab/tsunami_agent')
    tsunami.Target(address='0.0.0.0', version='v4')
    test_agent = tsunami_agent.AgentTsunami(definition, settings)

    test_agent.process(msg)


    mock_report_vulnerability.assert_called_once_with(entry=kb_entry,
        technical_detail=f'```json\n{data}\n```', risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH)




