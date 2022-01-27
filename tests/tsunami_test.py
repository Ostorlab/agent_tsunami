"""Unittests for tsunami class."""
import json

from agent.tsunami import tsunami


def _start_scan_success(self, target, output_file):
    data = {
        'scanStatus': 'SUCCEEDED',
        'scanFindings': []
    }
    with open(output_file, 'w', encoding='utf-8') as outfile:
        json.dump(data, outfile)


def _start_scan_failed(self, target, output_file):
    data = {
        'scanStatus': 'FAILED',
        'scanFindings': []
    }
    with open(output_file, 'w', encoding='utf-8') as outfile:
        json.dump(data, outfile)


def testTsunamiClass_WhenTsunamiScanStatusIsSuccess_ShouldReturnValidDict(agent_mock, mocker):
    """Tsunami class is responsible for running a scan using Tsunami scanned CLi on a specific target.
    when provided with valid Target the class method scan() should return a valid dict with all the findings from
    tsunami output file.
    """

    mocker.patch('agent.tsunami.tsunami.Tsunami._start_scan', _start_scan_success)
    target = tsunami.Target(address='0.0.0.0', version='v6')

    with tsunami.Tsunami() as tsunami_scanner:
        scan_result = tsunami_scanner.scan(target)
        assert 'vulnerabilities' in scan_result
        assert 'status' in scan_result
        assert 'success' in scan_result['status']


def testTsunamiClass_WhenTsunamiScanFailed_ShouldReturnValidDict(agent_mock, mocker):
    """Tsunami class is responsible for running a scan using Tsunami scanned CLi on a specific target.
    when provided with valid Target the class method scan() should return a valid dict with all the findings from
    tsunami output file.
    """

    mocker.patch('agent.tsunami.tsunami.Tsunami._start_scan', _start_scan_failed)
    target = tsunami.Target(address='0.0.0.0', version='v6')
    with tsunami.Tsunami() as tsunami_scanner:
        scan_result = tsunami_scanner.scan(target)
        assert 'vulnerabilities' in scan_result
        assert 'status' in scan_result
        assert 'failed' in scan_result['status']
