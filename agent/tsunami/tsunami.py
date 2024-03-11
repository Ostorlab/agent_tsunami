"""Simple wrapper for tsunami scanner."""

import json
import logging
import subprocess
import tempfile
from typing import Optional, Dict, Any
import types

import func_timeout

from agent.tsunami.factory import preapre_tagets_tools as tools


TIMEOUT = 300

logger = logging.getLogger(__name__)


class Tsunami:
    """Tsunami wrapper to enable using tsunami scanner from ostorlab agent class."""

    _output_file = None

    def __enter__(self) -> Any:
        self._output_file = tempfile.NamedTemporaryFile(
            suffix=".json",
            prefix="tsunami",
            dir="/tmp",
        )
        return self

    def _get_target_arg(self, target: tools.Target) -> str:
        """Select the right argument for tsunami CLI based on the target type.

        Args:
            target: Target.

        Returns:
            - argument for tsunami CLi target.

        Raises:
            - ValueError: the provided  ip version is incorrect.
        """
        if target.address is not None:
            if target.version == "v4":
                return f"--ip-v4-target={target.address}"
            elif target.version == "v6":
                return f"--ip-v6-target={target.address}"
            else:
                raise ValueError(f"Incorrect ip version {target.version}.")
        elif target.domain is not None:
            return f"--hostname-target={target.domain}"
        else:
            raise ValueError("Could not find any target.")

    @func_timeout.func_set_timeout(TIMEOUT)  # type: ignore[misc]
    def _start_scan(self, target: tools.Target, output_file: str) -> None:
        """Run a tsunami scan using python subprocess.

        Args:
            target:  Target
            output_file: name of the output.
        """

        logger.info("staring a new scan for %s .", target.address)

        tsunami_command = [
            "java",
            "-cp",
            "/usr/tsunami/tsunami.jar:/usr/tsunami/plugins/*",
            "-Dtsunami-config.location=/usr/tsunami/tsunami.yaml",
            "com.google.tsunami.main.cli.TsunamiCli",
            "--scan-results-local-output-format=JSON",
            f"--scan-results-local-output-filename={output_file}",
            self._get_target_arg(target),
        ]

        subprocess.run(
            tsunami_command, encoding="utf-8", stdout=subprocess.DEVNULL, check=True
        )

    def _parse_result(self, output_file: Optional[Any]) -> Dict[str, Any]:
        """After the scan is done, parse the output json file into a dict of the scan Findings.
        returns:
            - scan results.
        """
        json_result: Dict[str, Any] = {"vulnerabilities": []}
        if output_file is not None:
            logger.info("scan is done, parsing the results from %s.", output_file.name)
            tsunami_result = json.load(output_file)

            if (
                "SUCCEEDED" in tsunami_result["scanStatus"]
                and "scanFindings" in tsunami_result.keys()
            ):
                json_result["status"] = "success"
                logger.debug("scan status: SUCCEEDED")
                for vul in tsunami_result["scanFindings"]:
                    json_result["vulnerabilities"].append(vul)
            else:
                json_result["status"] = "failed"
        return json_result

    def scan(self, target: tools.Target) -> Dict[str, Any]:
        """Start a scan, wait for the scan results and clean the scan output.

        returns:
         - Scan results from tsunami.
        """
        try:
            if self._output_file is not None:
                self._start_scan(target, self._output_file.name)
                findings = self._parse_result(self._output_file)
                return findings
            else:
                return {}
        except func_timeout.exceptions.FunctionTimedOut:
            return {}

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> Any:
        if self._output_file is not None:
            self._output_file.close()
        return self
