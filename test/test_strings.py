# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool Strings tests
"""

from pathlib import Path

import pytest

from cve_bin_tool.async_utils import aio_run_command
from cve_bin_tool.strings import Strings

ASSETS_PATH = Path(__file__).parent.resolve() / "assets"


class TestStrings:
    """Tests the CVE Bin Tool Strings"""

    @classmethod
    def setup_class(cls):
        cls.strings = Strings()

    @pytest.mark.asyncio
    async def _parse_test(self, filename):
        """Helper function to parse a binary file and check whether
        the given string is in the parsed result"""
        self.strings.filename = str(ASSETS_PATH / filename)
        binutils_strings, _, _ = await aio_run_command(
            ["strings", self.strings.filename]
        )
        ours = await self.strings.aio_parse()
        for theirs in binutils_strings.splitlines():
            assert theirs.decode("utf-8") in ours

    @pytest.mark.asyncio
    async def test_curl_7_34_0(self):
        """Stringsing test-curl-7.34.0.out"""
        await self._parse_test("test-curl-7.34.0.out")

    @pytest.mark.asyncio
    async def test_kerberos_1_15_1(self):
        """Stringsing test-kerberos-5-1.15.1.out"""
        await self._parse_test("test-kerberos-5-1.15.1.out")
