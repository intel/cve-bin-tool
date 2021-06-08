# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Resource definitions and helper utilities for tests.
"""
import asyncio
import os
import shutil
import sys
import tempfile
import unittest
from urllib.request import urlopen

import pytest

from cve_bin_tool.async_utils import get_event_loop

CURL_7_20_0_RPM = "curl-7.20.0-4.fc13.x86_64.rpm"
CURL_7_20_0_URL = (
    "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/13/Everything/x86_64/os/Packages/"
    + CURL_7_20_0_RPM
)
TMUX_DEB_NAME = "tmux_1.8-5_amd64.deb"
TMUX_DEB = "https://mirrors.cat.pdx.edu/ubuntu/pool/main/t/tmux/" + TMUX_DEB_NAME


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


@pytest.fixture
def event_loop():
    yield get_event_loop()
