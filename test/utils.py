# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Resource definitions and helper utilities for tests.
"""
import os
import shutil
import tempfile
from pathlib import Path

import pytest
import requests

from cve_bin_tool.async_utils import get_event_loop
from cve_bin_tool.error_handler import ERROR_CODES, NetworkConnectionError
from cve_bin_tool.log import LOGGER

TEST_DIR_PATH = Path(__file__).parent.resolve()
CURL_7_20_0_RPM = "curl-7.20.0-4.fc13.x86_64.rpm"
CURL_7_20_0_URL = (
    "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/13/Everything/x86_64/os/Packages/"
    + CURL_7_20_0_RPM
)
DEB_FILE_PATH = TEST_DIR_PATH / "assets" / "test.deb"
DEB_ZST_FILE_PATH = TEST_DIR_PATH / "assets" / "test-zst.deb"
IPK_FILE_PATH = TEST_DIR_PATH / "assets" / "test.ipk"
ZST_FILE_PATH = TEST_DIR_PATH / "assets" / "test.tar.zst"
DOVECOT_FILE_PATH = (
    TEST_DIR_PATH / "condensed-downloads" / "dovecot-2.3.14-1.fc34.i686.rpm"
)
PKG_FILE_PATH = TEST_DIR_PATH / "assets" / "test.pkg"
CAB_TEST_FILE_PATH = TEST_DIR_PATH / "assets" / "cab-test-python3.8.cab"
APK_FILE_PATH = TEST_DIR_PATH / "assets" / "test.apk"


class TempDirTest:
    """For tests that need a temp directory"""

    @classmethod
    def setup_class(cls):
        cls.tempdir = tempfile.mkdtemp()

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.tempdir)


def download_file(url, target):
    """helper method to download a file"""
    # timeout = 300s = 5min. This is a total guess of a valid timeout.
    try:
        download = requests.get(url, timeout=300)
        with open(target, "wb") as target_file:
            target_file.write(download.content)
        download.close()
    except requests.exceptions.ConnectionError as e:
        LOGGER.debug(f"Error: {e}")
        LOGGER.critical(
            f"Please make sure you have a working internet connection: {ERROR_CODES[NetworkConnectionError]}"
        )


def LONG_TESTS() -> bool:
    # override LONG_TESTS with environment variable if available
    env_var = os.getenv("LONG_TESTS")
    if env_var:
        return bool(int(env_var))
    return False


def EXTERNAL_SYSTEM() -> bool:
    env_var = os.getenv("EXTERNAL_SYSTEM")
    if env_var:
        return bool(int(env_var))
    return False


@pytest.fixture
def event_loop():
    yield get_event_loop()
