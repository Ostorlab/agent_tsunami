"""Unittests for agent."""
import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent import message
from ostorlab.agent.message.serializer import NoMatchingPackageNameError
from ostorlab.runtimes import definitions as runtime_definitions

from agent import agent


def testTsunamiAgent_WhenMessageHaveInvalidIpVersion_ShouldRaiseValueErrorException(agent_mock):
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


