"""Unittests for tsunami class."""

from agent.tsunami import tsunami


def testTsunamiClass_WhenTsunamiScanStatusIsSuccess_ShouldReturnValidDict(agent_mock, mocker, start_scan_success):
    """Tsunami class is responsible for running a scan using Tsunami scanned CLi on a specific target.
    when provided with valid Target the class method scan() should return a valid dict with all the findings from
    tsunami output file.
    """

    mocker.patch('agent.tsunami.tsunami.Tsunami._start_scan', start_scan_success)
    target = tsunami.Target(address='0.0.0.0', version='v6')

    with tsunami.Tsunami() as tsunami_scanner:
        scan_result = tsunami_scanner.scan(target)
        assert 'vulnerabilities' in scan_result
        assert 'status' in scan_result
        assert 'success' in scan_result['status']


def testTsunamiClass_WhenTsunamiScanFailed_ShouldReturnValidDict(agent_mock, mocker, start_scan_failed):
    """Tsunami class is responsible for running a scan using Tsunami scanned CLi on a specific target.
    when provided with valid Target the class method scan() should return a valid dict with all the findings from
    tsunami output file.
    """

    mocker.patch('agent.tsunami.tsunami.Tsunami._start_scan', start_scan_failed)
    target = tsunami.Target(address='0.0.0.0', version='v6')
    with tsunami.Tsunami() as tsunami_scanner:
        scan_result = tsunami_scanner.scan(target)
        assert 'vulnerabilities' in scan_result
        assert 'status' in scan_result
        assert 'failed' in scan_result['status']
