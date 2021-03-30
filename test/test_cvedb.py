# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import datetime
import shutil
import sys
import tempfile
from test.utils import event_loop

import aiohttp
import pytest

from cve_bin_tool.cvedb import CVEDB


class TestCVEDB:
    @classmethod
    def setup_class(cls):
        cls.cvedb = CVEDB(cachedir=tempfile.mkdtemp(prefix="cvedb-"))

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.cvedb.cachedir)

    @pytest.mark.asyncio
    async def test_00_getmeta(self):
        connector = aiohttp.TCPConnector(limit_per_host=19)
        async with aiohttp.ClientSession(
            connector=connector, trust_env=True
        ) as session:
            _jsonurl, meta = await self.cvedb.getmeta(
                session,
                "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta",
            )
        assert "sha256" in meta

    @pytest.mark.asyncio
    async def test_01_nist_scrape(self):
        async with aiohttp.ClientSession(trust_env=True) as session:
            jsonshas = await self.cvedb.nist_scrape(session)
            assert (
                "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.gz"
                in jsonshas
            )

    @pytest.mark.asyncio
    async def test_02_cache_update(self):
        async with aiohttp.ClientSession(trust_env=True) as session:
            jsonurl, meta = await self.cvedb.getmeta(
                session, "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.meta"
            )
            assert "sha256" in meta
            await self.cvedb.cache_update(session, jsonurl, meta["sha256"])

    @pytest.mark.asyncio
    async def test_03_refresh(self):
        await self.cvedb.refresh()
        years = self.cvedb.nvd_years()
        for year in range(2002, datetime.datetime.now().year):
            assert year in years, f"Missing NVD data for {year}"
