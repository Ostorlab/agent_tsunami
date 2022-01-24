from dataclasses import dataclass
import subprocess
import logging

logger = logging.getLogger(__name__)


@dataclass
class Tsunami:
    target: str
    target_type: str

    def _get_target_arg(self):
        if self.target_type == 'v4':
            return f'--ip-v4-target={self.target}'
        elif self.target_type == 'v6':
            return f'--ip-v4-target={self.target}'

    def start_scan(self):
        tsunami_command = ["java",
                           "-cp",
                           "/usr/tsunami/tsunami.jar:/usr/tsunami/plugins/*",
                           "-Dtsunami-config.location=/usr/tsunami/tsunami.yaml",
                           "com.google.tsunami.main.cli.TsunamiCli",
                           "--scan-results-local-output-format=JSON",
                           "--scan-results-local-output-filename=./tsunami-output.json",
                           self._get_target_arg()
                           ]
        subprocess.run(tsunami_command, encoding='utf-8', stdout=subprocess.PIPE)

        pass

    def parse_result(self):
        pass

    def clear_results(self):
        pass
