"""Setup and start vpn"""
import datetime
import logging
import pathlib
import subprocess
from typing import List

logger = logging.getLogger(__name__)


class Error(Exception):
    """Base Custom Error Class."""


class RunCommandError(Error):
    """Error when running a command using a subprocess."""


class VpnSetupError(Error):
    """Error when running a command using a subprocess."""


DNS_RESOLV_CONFIG_PATH = pathlib.Path("/etc/wireguard/wg0.conf")
WIREGUARD_CONFIG_FILE_PATH = pathlib.Path("/etc/resolv.conf")
JAVA_COMMAND_TIMEOUT = datetime.timedelta(minutes=5)


def _exec_command(command: List[str]) -> None:
    """Execute a command.
    Args:
        command: The command to execute.
    """
    try:
        logger.info("%s", " ".join(command))
        output = subprocess.run(
            command,
            capture_output=True,
            timeout=JAVA_COMMAND_TIMEOUT.seconds,
            check=True,
        )
        logger.debug("process returned: %s", output.returncode)
        logger.debug("output: %s", output.stdout)
        logger.debug("err: %s", output.stderr)

    except subprocess.CalledProcessError as e:
        raise RunCommandError(
            f'An error occurred while running the command {" ".join(command)}'
        ) from e
    except subprocess.TimeoutExpired:
        logger.warning("Java command timed out for command %s", " ".join(command))


def enable_vpn(vpn_config: str, dns_config: str) -> None:
    """
    Setup and start vpn for the provided country.
    Args:
        vpn_config: country to set up for.
        dns_config: DNS configuration.
    Raises: VpnSetupError in case of no config available for the provided country.
    """
    # Write the configuration to the file /etc/wireguard/wg0.conf
    with open(WIREGUARD_CONFIG_FILE_PATH, "w", encoding="UTF-8") as f:
        f.write(vpn_config)
    _exec_command(["wg-quick", "up", "wg0"])
    with open(DNS_RESOLV_CONFIG_PATH, "w", encoding="UTF-8") as f:
        f.write(dns_config)
