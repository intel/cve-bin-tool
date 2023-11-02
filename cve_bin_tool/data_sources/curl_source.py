# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
import logging
from pathlib import Path

import aiohttp

from cve_bin_tool.async_utils import FileIO, RateLimiter
from cve_bin_tool.data_sources import (
    DISK_LOCATION_BACKUP,
    DISK_LOCATION_DEFAULT,
    Data_Source,
)
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.log import LOGGER
from cve_bin_tool.version import HTTP_HEADERS

logging.basicConfig(level=logging.DEBUG)


class Curl_Source(Data_Source):
    """Represents a data source for retrieving information about vulnerabilities in cURL."""

    SOURCE = "Curl"
    CACHEDIR = DISK_LOCATION_DEFAULT
    BACKUPCACHEDIR = DISK_LOCATION_BACKUP
    LOGGER = LOGGER.getChild("CVEDB")
    DATA_SOURCE_LINK = "https://curl.se/docs/vuln.json"

    def __init__(self, error_mode=ErrorMode.TruncTrace):
        """Initialize a Curl_Source instance. Args: error_mode (ErrorMode): The error mode to be used."""
        self.cve_list = None
        self.cachedir = self.CACHEDIR
        self.backup_cachedir = self.BACKUPCACHEDIR
        self.error_mode = error_mode
        self.session = None
        self.affected_data = None
        self.source_name = self.SOURCE
        self.vulnerability_data = []

    async def get_cve_data(self):
        """Get cURL vulnerability data. Fetches the cURL vulnerability data and retrieves a list of affected data."""
        await self.fetch_cves()
        self.get_cve_list()

        return (None, self.affected_data), self.source_name

    async def fetch_cves(self):
        """Fetch cURL vulnerabilities data."""
        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=19)
            self.session = RateLimiter(
                aiohttp.ClientSession(
                    connector=connector, headers=HTTP_HEADERS, trust_env=True
                )
            )
        await self.download_curl_vulnerabilities(self.session)
        await self.session.close()

    async def download_curl_vulnerabilities(self, session: RateLimiter) -> None:
        """Download cURL vulnerability data and save it to a file. Args: session (RateLimiter): The session to use for the HTTP request."""
        async with await session.get(self.DATA_SOURCE_LINK) as response:
            response.raise_for_status()
            self.vulnerability_data = await response.json()
        path = Path(str(Path(self.cachedir) / "vuln.json"))
        filepath = path.resolve()
        async with FileIO(filepath, "w") as f:
            await f.write(json.dumps(self.vulnerability_data, indent=4))

    def get_cve_list(self):
        """Get a list of affected cURL vulnerabilities."""
        self.affected_data = []

        for cve in self.vulnerability_data:
            affected = {
                "cve_id": cve["aliases"][0],
                "vendor": "haxx",
                "product": "curl",
                "version": "*",
                "versionStartIncluding": cve["affected"][0]["ranges"][0]["events"][0][
                    "introduced"
                ],
                "versionStartExcluding": "",
                "versionEndIncluding": cve["affected"][0]["versions"][0],
                "versionEndExcluding": "",
            }
            self.affected_data.append(affected)

        return self.affected_data
