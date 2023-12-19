"""Pytest fixtures for the Tsunami agent"""
import json
import pathlib
from typing import List, Dict, Union

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions

from agent import tsunami_agent


@pytest.fixture
def fixture_tsunami_agent_with_vpn(
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
) -> tsunami_agent.AgentTsunami:
    del agent_mock, agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        agent_definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/tsunami",
            redis_url="redis://guest:guest@localhost:6379",
            args=[
                defintions.Arg(
                    name="vpn_config",
                    type="string",
                    value=json.dumps("FAKE_VPN_CONFIG").encode(),
                ),
                defintions.Arg(
                    name="dns_config",
                    type="string",
                    value=json.dumps("FAKE_DNS_CONFIG").encode(),
                ),
            ],
        )

        agent = tsunami_agent.AgentTsunami(agent_definition, settings)
        return agent


@pytest.fixture(scope="function", name="tsunami_agent")
def fixture_tsunami_agent(
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
) -> tsunami_agent.AgentTsunami:
    del agent_mock, agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        definition.args[0]["value"] = "([a-zA-Z]+://ostorlab.co/?.*)"
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/tsunami", redis_url="redis://guest:guest@localhost:6379"
        )

        agent = tsunami_agent.AgentTsunami(definition, settings)
        return agent


@pytest.fixture(scope="function", name="tsunami_agent_no_scope")
def fixture_tsunami_agent_no_scope(
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
) -> tsunami_agent.AgentTsunami:
    del agent_mock, agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/tsunami", redis_url="redis://guest:guest@localhost:6379"
        )

        agent = tsunami_agent.AgentTsunami(definition, settings)
        return agent


@pytest.fixture
def ip_small_range_message() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 with a small mask to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "42.42.42.42", "mask": "31", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv4_with_mask8() -> message.Message:
    """Creates a message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "192.168.1.17", "mask": "8", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv4_with_mask16() -> message.Message:
    """Creates a message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "192.168.1.17", "mask": "16", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv6_with_mask64() -> message.Message:
    """Creates a message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:db8:3333:4444:5555:6666:7777:8888",
        "mask": "64",
        "version": 6,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv6_with_mask112() -> message.Message:
    """Creates a message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:db8:3333:4444:5555:6666:7777:8888",
        "mask": "112",
        "version": 6,
    }
    return message.Message.from_data(selector, data=msg_data)
