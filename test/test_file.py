# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool file tests
"""
from pathlib import Path

import pytest

from cve_bin_tool.async_utils import NamedTemporaryFile, aio_rmfile
from cve_bin_tool.file import aio_is_binary

ASSETS_PATH = Path(__file__).parent.resolve() / "assets"


class TestFile:
    """Tests the CVE Bin Tool file binary checker."""

    @pytest.mark.asyncio
    async def _check_test(self, file_type):
        """Helper function to parse a binary file and check whether
        the given string is in the parsed result"""
        async with NamedTemporaryFile("w+b", suffix=file_type, delete=False) as f:
            if file_type == "out":
                # write magic signature
                await f.write(b"\x7f\x45\x4c\x46\x02\x01\x01\x03\n")
                await f.seek(0)
                assert await aio_is_binary(f.name)
            else:
                await f.write(b"some other data\n")
                await f.seek(0)
                assert not await aio_is_binary(f.name)
        await aio_rmfile(f.name)

    @pytest.mark.asyncio
    async def test_binary_out_file(self):
        """file *.out"""
        await self._check_test("out")

    @pytest.mark.asyncio
    async def test_source_file(self):
        """file *.c"""
        await self._check_test("c")

    @pytest.mark.asyncio
    async def test_single_byte_file(self):
        """file single-byte"""
        assert not await aio_is_binary(str(ASSETS_PATH / "single-byte.txt"))

    @pytest.mark.asyncio
    async def test_windows(self):
        """file single-byte"""
        assert await aio_is_binary(str(ASSETS_PATH / "windows.txt"))
