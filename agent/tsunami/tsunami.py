"""Simple wrapper for tsunami scanner."""
import json
import re
from dataclasses import dataclass
import subprocess
import logging
import os

logger = logging.getLogger(__name__)


@dataclass
class Tsunami:
    """Tsunami wrapper to enable using tsunami scanner from ostorlab agent class."""
    target: str
    target_type: str

    @property
    def _output_file_name(self):
        """Generate a unique name for the output file."""
        output_file_name = re.sub(r'[^\w\s-]', '', self.target.lower())
        output_file_name = re.sub(r'[-\s]+', '-', output_file_name).strip('-_')
        return f'./tsunami_output_{output_file_name}.json'

    def _get_target_arg(self):
        """Select the right argument for tsunami CLI based on the target type"""
        if self.target_type == 'v4':
            return f'--ip-v4-target={self.target}'
        elif self.target_type == 'v6':
            return f'--ip-v4-target={self.target}'

    def _start_scan(self):
        """Run a tsunami scan using python subprocess."""
        logger.info(f'Staring a new scan for {self.target}.')
        tsunami_command = ["java",
                           "-cp",
                           "/usr/tsunami/tsunami.jar:/usr/tsunami/plugins/*",
                           "-Dtsunami-config.location=/usr/tsunami/tsunami.yaml",
                           "com.google.tsunami.main.cli.TsunamiCli",
                           "--scan-results-local-output-format=JSON",
                           f'--scan-results-local-output-filename={self._output_file_name}',
                           self._get_target_arg()
                           ]
        subprocess.run(tsunami_command, encoding='utf-8', stdout=subprocess.PIPE)

    def _parse_result(self):
        """After the scan is done, parse the output json file into a dict of the scan Findings.
        returns:
            - scan results.
        """
        logger.info(f'Scan is done Parsing the results from  {self._output_file_name}.')
        f = open(self._output_file_name)
        tsunami_result = json.load(f)
        json_result = {
            'vulnerabilities': []
        }
        if 'SUCCEEDED' in tsunami_result['scanStatus']:
            logger.info(f'Scan status: SUCCEEDED')
            for vul in tsunami_result['scanFindings']:
                # json_result["vulnerabilities"].append(vul['vulnerability'])
                json_result["vulnerabilities"].append(vul)
        f.close()
        return json_result

    def scan(self):
        """Start a scan, wait for the scan results and clean the scan output.

           returns:
            - scan results.
        """
        self._start_scan()
        findings = self._parse_result()
        self._clear_results()
        return findings

    def _clear_results(self):
        """After a can is done, we delete the output file from the system."""
        os.remove(self._output_file_name)
