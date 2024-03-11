"""Test VPN setup."""

import io
import subprocess
from unittest.mock import mock_open

from pytest_mock import plugin

from agent import tsunami_agent

EXEC_COMMAND_OUTPUT = subprocess.CompletedProcess(
    args="",
    returncode=0,
    stderr=io.BytesIO(b"Fake stderr"),
    stdout=io.BytesIO(b"Fake stdout"),
)


def testVpnSetup_whenVpnCountryIsPresent_shouldCallSetupVpnSetupVpnWithRightConfig(
    fixture_tsunami_agent_with_vpn: tsunami_agent.AgentTsunami,
    mocker: plugin.MockerFixture,
) -> None:
    """Test when vpn country argument is provided should call setup vpn"""
    mock_write = mocker.patch("builtins.open", new_callable=mock_open())
    mocked_subprocess = mocker.patch("subprocess.run", return_value=EXEC_COMMAND_OUTPUT)

    fixture_tsunami_agent_with_vpn.start()

    mocked_subprocess.assert_called()
    assert " ".join(mocked_subprocess.call_args_list[0][0][0]) == "wg-quick up wg0"
    assert str(mock_write.call_args_list[0][0][0]) == "/etc/wireguard/wg0.conf"
    assert str(mock_write.call_args_list[1][0][0]) == "/etc/resolv.conf"
