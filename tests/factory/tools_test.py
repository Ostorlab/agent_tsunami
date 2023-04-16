"""Unit test for factory tools."""
import pytest
import ipaddress

from ostorlab.agent.message import message

from agent.tsunami.factory import preapre_tagets_tools as tools


@pytest.mark.parametrize(
    "input_message,expected",
    [
        (
            message.Message.from_data(
                selector="v3.asset.domain_name", data={"name": "ostorlab.co"}
            ),
            [
                tools.Target(
                    address=None,
                    version=None,
                    ip_network=None,
                    domain="http://ostorlab.co",
                    url="http://ostorlab.co",
                )
            ],
        ),
        (
            message.Message.from_data(
                selector="v3.asset.ip.v4", data={"version": 4, "host": "0.0.0.0"}
            ),
            [
                tools.Target(
                    address="0.0.0.0",
                    version="v4",
                    ip_network=ipaddress.IPv4Network("0.0.0.0/32"),
                    domain=None,
                    url=None,
                )
            ],
        ),
        (
            message.Message.from_data(
                selector="v3.asset.domain_name.service",
                data={"name": "ostorlab.co", "port": 6000, "schema": "https"},
            ),
            [
                tools.Target(
                    address=None,
                    version=None,
                    ip_network=None,
                    domain="https://ostorlab.co:6000",
                    url="https://ostorlab.co:6000",
                )
            ],
        ),
        (
            message.Message.from_data(
                selector="v3.asset.link",
                data={"url": "test.ostorlab.co", "method": "GET"},
            ),
            [
                tools.Target(
                    address=None,
                    version=None,
                    ip_network=None,
                    domain="",
                    url="test.ostorlab.co",
                )
            ],
        ),
    ],
)
def testTsunamyFactory_whenPrepareMessages_prepareTarget(
    input_message: message.Message, expected: list[tools.Target]
) -> None:
    assert tools.prepare_targets(message=input_message, args={}) == expected
