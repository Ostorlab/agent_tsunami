"""Module for preparing tsunami targets."""

import dataclasses
import ipaddress
import logging
from typing import Optional, Any
from urllib import parse

from ostorlab.agent.message import message as msg

IPV4_CIDR_LIMIT = 16
IPV6_CIDR_LIMIT = 112


@dataclasses.dataclass
class Target:
    """Data Class for tsunami target."""

    address: Optional[str] = None
    version: Optional[str] = None
    ip_network: Optional[ipaddress.IPv4Network | ipaddress.IPv6Network] = None
    domain: Optional[str] = None
    url: Optional[str] = None


def _get_schema(message: msg.Message, args: dict[str, Any]) -> str:
    """Returns the schema to be used for the target."""
    if message.data.get("schema") is not None:
        return str(message.data["schema"])
    elif message.data.get("protocol") is not None:
        return str(message.data["protocol"])
    elif args.get("https") is True:
        return "https"
    else:
        return "http"


def _prepare_domain_target(message: msg.Message, args: dict[str, Any]) -> Target:
    target = str(message.data["name"])
    schema = _get_schema(message, args)
    port = message.data.get("port")
    if schema == "https" and port not in [443, None]:
        url = f"https://{target}:{port}"
    elif schema == "https":
        url = f"https://{target}"
    elif port == 80:
        url = f"http://{target}"
    elif port is None:
        url = f"{schema}://{target}"
    else:
        url = f"{schema}://{target}:{port}"
    return Target(domain=url, url=url)


def _prepare_url_target(message: msg.Message) -> Target:
    link = str(message.data["url"])
    return Target(domain=str(parse.urlparse(link).netloc), url=link)


def _prepare_ip_targets(message: msg.Message, host: str) -> list[Target]:
    mask = message.data.get("mask")
    version = message.data.get("version")
    if version == 6:
        if mask is not None and int(mask) < IPV6_CIDR_LIMIT:
            raise ValueError(f"Subnet mask below {IPV6_CIDR_LIMIT} is not supported.")
        version = "v6"
    elif version == 4:
        if mask is not None and int(mask) < IPV4_CIDR_LIMIT:
            raise ValueError(f"Subnet mask below {IPV4_CIDR_LIMIT} is not supported.")
        version = "v4"
    else:
        raise ValueError(f"Incorrect ip version {version}")
    try:
        if mask is None:
            ip_network = ipaddress.ip_network(host)
        else:
            ip_network = ipaddress.ip_network(f"""{host}/{mask}""")
        return [
            Target(version=version, address=str(host), ip_network=ip_network)
            for host in ip_network.hosts()
        ]
    except ValueError:
        logging.info(
            "Incorrect %s / %s",
            {host},
            {mask},
        )
        return []


def prepare_targets(message: msg.Message, args: dict[str, Any]) -> list[Target]:
    """Prepare Targets and dispatch it to prepare: domain/link and hosts."""
    # domain_name message
    if message.data.get("name") is not None:
        return [_prepare_domain_target(message, args)]
    # link message
    if message.data.get("url") is not None:
        return [_prepare_url_target(message)]
    # IP message
    host = message.data.get("host")
    if host is not None:
        return _prepare_ip_targets(message, host)
    else:
        raise ValueError("Message is invalid.")
