# tests/test_utils.py

from shodan_downloader.utils import setup_logging

def test_setup_logging_does_not_crash():
    setup_logging(verbose=False)
    setup_logging(verbose=True)