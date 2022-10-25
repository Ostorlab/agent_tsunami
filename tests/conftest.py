"""Pytest fixtures for the Tsunami agent"""
import pathlib
from typing import List, Dict, Union

import pytest
from ostorlab.agent.message import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import tsunami_agent


@pytest.fixture(scope='function', name='tsunami_agent')
def fixture_tsunami_agent(agent_mock: List[message.Message],
                          agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]]) -> tsunami_agent.AgentTsunami:
    del agent_mock, agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        definition.args[0]['value'] = '([a-zA-Z]+://ostorlab.co/?.*)'
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/tsunami',
            redis_url='redis://guest:guest@localhost:6379'
        )

        agent = tsunami_agent.AgentTsunami(definition, settings)
        return agent


@pytest.fixture(scope='function', name='tsunami_agent_no_scope')
def fixture_tsunami_agent_no_scope(agent_mock: List[message.Message],
                                   agent_persist_mock: Dict[
                                       Union[str, bytes], Union[str, bytes]]) -> tsunami_agent.AgentTsunami:
    del agent_mock, agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/tsunami',
            redis_url='redis://guest:guest@localhost:6379'
        )

        agent = tsunami_agent.AgentTsunami(definition, settings)
        return agent



@pytest.fixture
def ip_small_range_message() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 with a small mask to be used by the agent for testing purposes."""
    selector = 'v3.asset.ip.v4'
    msg_data = {
        'host': '42.42.42.42',
        'mask': '31',
        'version': 4
    }
    return message.Message.from_data(selector, data=msg_data)
