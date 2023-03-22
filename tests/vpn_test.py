"""Test VPN setup."""
from pytest_mock import plugin
from agent import tsunami_agent


def _testVpnSetup_whenVpnCountryIsPresent_shouldCallSetupVpnSetupVpnWithRightConfig(
    fixture_tsunami_agent_with_vpn: tsunami_agent.AgentTsunami,
    mocker: plugin.MockerFixture,
) -> None:
    """Test when vpn country argument is provided should call setup vpn"""
    mocked_vpn_setup = mocker.patch("agent.vpn._exec_command", return_value=None)

    fixture_tsunami_agent_with_vpn.start()

    mocked_vpn_setup.assert_called()
    assert " ".join(mocked_vpn_setup.call_args_list[0][0][0]) == "wg-quick up wg0"
