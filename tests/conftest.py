"""
    Dummy contest.py for template_agent.

    If you don't know what this is for, just leave it empty.
    Read more about conftest.py under:
    - https://docs.pytest.org/en/stable/fixture.html
    - https://docs.pytest.org/en/stable/writing_plugins.html
"""

import json

import pytest


@pytest.fixture(scope='function')
def start_scan_success(**kwargs):
    def start_scan(self, target, output_file):
        data = {
            "scanStatus": "SUCCEEDED",
            "scanFindings": []
        }
        with open(output_file, 'w') as outfile:
            json.dump(data, outfile)

    return start_scan


@pytest.fixture(scope='function')
def start_scan_failed(**kwargs):
    def start_scan(self, target, output_file):
        data = {
            "scanStatus": "FAILED",
            "scanFindings": []
        }
        with open(output_file, 'w') as outfile:
            json.dump(data, outfile)

    return start_scan
