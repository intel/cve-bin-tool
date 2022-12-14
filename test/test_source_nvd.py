# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import shutil
import tempfile
from test.utils import EXTERNAL_SYSTEM

import aiohttp
import pytest

from cve_bin_tool.data_sources import nvd_source


class TestSourceNVD:
    @classmethod
    def setup_class(cls):
        cls.nvd = nvd_source.NVD_Source()
        cls.nvd.cachedir = tempfile.mkdtemp(prefix="cvedb-")

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.nvd.cachedir)

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not EXTERNAL_SYSTEM(), reason="Skipping NVD calls due to rate limits"
    )
    async def test_00_getmeta(self):
        connector = aiohttp.TCPConnector(limit_per_host=19)
        async with aiohttp.ClientSession(
            connector=connector, trust_env=True
        ) as session:
            _jsonurl, meta = await self.nvd.getmeta(
                session,
                "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta",
            )
        assert "sha256" in meta

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not EXTERNAL_SYSTEM(), reason="Skipping NVD calls due to rate limits"
    )
    async def test_01_cache_update(self):
        async with aiohttp.ClientSession(trust_env=True) as session:
            jsonurl, meta = await self.nvd.getmeta(
                session, "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.meta"
            )
            assert "sha256" in meta
            await self.nvd.cache_update(session, jsonurl, meta["sha256"])
