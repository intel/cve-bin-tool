"""
Resource definitions and helper utilities for tests.
"""
import os
import shutil
import tempfile
import unittest

# Try python3 dependency, fall back if not available
try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen

CURL_7_20_0_RPM = "curl-7.20.0-4.fc13.x86_64.rpm"
CURL_7_20_0_URL = (
    "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/13/Everything/x86_64/os/Packages/"
    + CURL_7_20_0_RPM
)
VMWARE_CAB = "https://master.dl.sourceforge.net/project/winpe/VmWare%20Drivers/VmWare%20Drivers%20v1.1/vmware-1.1.cab"
TMUX_DEB_NAME = "tmux_1.8-5_amd64.deb"
TMUX_DEB = "https://mirrors.cat.pdx.edu/ubuntu/pool/main/t/tmux/" + TMUX_DEB_NAME


class TempDirTest(unittest.TestCase):
    """ For tests that need a temp directory """

    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tempdir)


def download_file(url, target):
    """ helper method to download a file """
    download = urlopen(url)
    with open(target, "wb") as target_file:
        target_file.write(download.read())
    download.close()


def LONG_TESTS():
    LONG_TESTS = 0
    # override LONG_TESTS with environment variable if available
    if os.getenv("LONG_TESTS"):
        LONG_TESTS = int(os.getenv("LONG_TESTS"))
    return LONG_TESTS
