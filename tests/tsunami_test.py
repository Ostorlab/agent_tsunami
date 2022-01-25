"""Unittests for tsunami class."""
import json
import logging

from rich.logging import RichHandler

from agent.tsunami import tsunami

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')


def testTsunamiClass_WhenTsunamiScanStatusIsSuccess_ShouldReturnValidDict(agent_mock, mocker, start_scan_success):
    """Tsunami class is responsible for running a scan using Tsunami scanned CLi on a specific target.
    when provided with valid Target the class method scan() should return a valid dict with all the findings from
    tsunami output file.
    """

    mocker.patch('agent.tsunami.tsunami.Tsunami._start_scan', start_scan_success)
    target = tsunami.Target(target_address='0.0.0.0', target_version='v6')

    scan_result = tsunami.Tsunami().scan(target)

    assert "vulnerabilities" in scan_result.keys()
    assert "status" in scan_result.keys()
    assert 'success' in scan_result['status']


def testTsunamiClass_WhenTsunamiScanFailed_ShouldReturnValidDict(agent_mock, mocker, start_scan_failed):
    """Tsunami class is responsible for running a scan using Tsunami scanned CLi on a specific target.
    when provided with valid Target the class method scan() should return a valid dict with all the findings from
    tsunami output file.
    """

    mocker.patch('agent.tsunami.tsunami.Tsunami._start_scan', start_scan_failed)
    target = tsunami.Target(target_address='0.0.0.0', target_version='v6')

    scan_result = tsunami.Tsunami().scan(target)

    assert "vulnerabilities" in scan_result.keys()
    assert "status" in scan_result.keys()
    assert 'failed' in scan_result['status']
