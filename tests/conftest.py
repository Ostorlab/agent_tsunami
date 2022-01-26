"""Setup test config for tsunami agent."""

import json

import pytest


@pytest.fixture(scope='function')
def start_scan_success(**kwargs):
    def start_scan(self, target, output_file):
        data = {
            'scanStatus': 'SUCCEEDED',
            'scanFindings': []
        }
        with open(output_file,'w', encoding='utf-8') as outfile:
            json.dump(data, outfile)

    return start_scan


@pytest.fixture(scope='function')
def start_scan_failed(**kwargs):
    def start_scan(self, target, output_file):
        data = {
            'scanStatus': 'FAILED',
            'scanFindings': []
        }
        with open(output_file, 'w', encoding='utf-8') as outfile:
            json.dump(data, outfile)

    return start_scan
