"""Unit test for factory tools."""
import pytest
import ipaddress

from ostorlab.agent.message import message

from agent.tsunami.factory import preapre_tagets_tools as tools


msg_1 = message.Message.from_data(
    selector="v3.asset.domain_name", data={"name": "ostorlab.co"}
)

msg_2 = message.Message.from_data(
    selector="v3.asset.ip.v4", data={"version": 4, "host": "0.0.0.0"}
)

msg_3 = message.Message.from_data(
    selector="v3.asset.domain_name.service",
    data={"name": "ostorlab.co", "port": 6000, "schema": "https"},
)

msg_4 = message.Message.from_data(
    selector="v3.asset.link", data={"url": "test.ostorlab.co", "method": "GET"}
)


@pytest.mark.parametrize(
    "input_message,expected",
    [
        (
            msg_1,
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
            msg_2,
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
            msg_3,
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
            msg_4,
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
