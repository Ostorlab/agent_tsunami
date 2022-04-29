"""Pytest fixtures for the Tsunami agent"""
import pathlib

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import tsunami_agent

@pytest.fixture(scope='function', name='tsunami_agent')
def fixture_tsunami_agent(agent_mock):
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:

        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/tsunami'
        )

        agent = tsunami_agent.AgentTsunami(definition, settings)
        return agent
