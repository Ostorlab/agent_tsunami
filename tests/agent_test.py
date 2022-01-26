"""Unittests for agent."""

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent import message
from ostorlab.runtimes import definitions as runtime_definitions

from agent import agent
from agent.tsunami import tsunami


def testTsunamiAgent_WhenMessageHaveInvalidIpVersion_ShouldRaiseValueErrorException():
    """Test Tsunami agent when receiving a message with invalid ip version.
        Tsunami support ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """
    # providing invalid version
    msg = message.Message.from_data(selector='v3.asset.ip', data={'version': 15631, 'host': '0.0.0.0'})
    definition = agent_definitions.AgentDefinition(name='start_test_agent', out_selectors=['v3.report.vulnerability'])
    settings = runtime_definitions.AgentSettings(key='agent/ostorlab/tsunami_agent')
    test_agent = agent.AgentTsunami(definition, settings)

    with pytest.raises(ValueError):
        test_agent.process(msg)


def testTsunamiAgent_WhenTsunamiScanIsCalled_ShouldRaiseValueErrorException(mocker):
    """Test Tsunami agent when receiving a message with invalid ip version.
        Tsunami support ipv4, ipv6 and hostname (domain), therefore every received message
        should have a valid ip version, other-ways the agent should raise a ValueError exception.
    """

    mock_tsunami_scan = mocker.patch('agent.tsunami.tsunami.Tsunami.scan', return_value={'target': 0})
    msg = message.Message.from_data(selector='v3.asset.ip', data={'version': 4, 'host': '0.0.0.0'})
    definition = agent_definitions.AgentDefinition(name='start_test_agent', out_selectors=['v3.report.vulnerability'])
    settings = runtime_definitions.AgentSettings(key='agent/ostorlab/tsunami_agent')
    target = tsunami.Target(address='0.0.0.0', version='v4')
    test_agent = agent.AgentTsunami(definition, settings)

    test_agent.process(msg)

    mock_tsunami_scan.assert_called_once()
    assert mock_tsunami_scan.call_args.kwargs['target'].address == target.address
    assert mock_tsunami_scan.call_args.kwargs['target'].version == target.version
