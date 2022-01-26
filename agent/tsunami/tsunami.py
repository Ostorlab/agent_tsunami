"""Simple wrapper for tsunami scanner."""
import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Target:
    """Data Class for tsunami target."""
    address: str
    version: str


class Tsunami:
    """Tsunami wrapper to enable using tsunami scanner from ostorlab agent class."""
    _output_file = None

    def __enter__(self):
        self._output_file = tempfile.NamedTemporaryFile(suffix='.json', prefix='tsunami', dir='/tmp', )
        return self

    def _get_target_arg(self, target: Target):
        """Select the right argument for tsunami CLI based on the target type.

        Args:
            target: Target.

        Returns:
            - argument for tsunami CLi target.

        Raises:
            - ValueError: the provided  ip version is incorrect.
        """
        if target.version == 'v4':
            return f'--ip-v4-target={target.address}'
        elif target.version == 'v6':
            return f'--ip-v4-target={target.address}'
        else:
            raise ValueError(f'Incorrect ip version {target.version}.')

    def _start_scan(self, target, output_file: str):
        """Run a tsunami scan using python subprocess.

        Args:
            target:  Target
            output_file: name of the output.
        """
        logger.info('Staring a new scan for %s .', target.address)
        tsunami_command = ['java',
                           '-cp',
                           '/usr/tsunami/tsunami.jar:/usr/tsunami/plugins/*',
                           '-Dtsunami-config.location=/usr/tsunami/tsunami.yaml',
                           'com.google.tsunami.main.cli.TsunamiCli',
                           '--scan-results-local-output-format=JSON',
                           f'--scan-results-local-output-filename={output_file}',
                           self._get_target_arg(target)
                           ]

        subprocess.run(tsunami_command, encoding='utf-8', stdout=subprocess.DEVNULL, check=True)

    def _parse_result(self, output_file):
        """After the scan is done, parse the output json file into a dict of the scan Findings.
        returns:
            - scan results.
        """
        logger.info('Scan is done Parsing the results from %s.', output_file.name)
        tsunami_result = json.load(output_file)
        json_result = {
            'vulnerabilities': []
        }
        if 'SUCCEEDED' in tsunami_result['scanStatus'] and 'scanFindings' in tsunami_result.keys():
            json_result['status'] = 'success'
            logger.info('Scan status: SUCCEEDED')
            for vul in tsunami_result['scanFindings']:
                # json_result["vulnerabilities"].append(vul['vulnerability'])
                json_result['vulnerabilities'].append(vul)
        else:
            json_result['status'] = 'failed'
        return json_result

    def scan(self, target: Target):
        """Start a scan, wait for the scan results and clean the scan output.

           returns:
            - Scan results from tsunami.
        """
        self._start_scan(target, self._output_file.name)
        findings = self._parse_result(self._output_file)
        return findings

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._output_file.close()
        return self
