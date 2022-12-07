# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import glob
import json
import logging
import re
from pathlib import Path

import aiohttp
from bs4 import BeautifulSoup, NavigableString, ResultSet

from cve_bin_tool.async_utils import FileIO, RateLimiter
from cve_bin_tool.data_sources import (
    DISK_LOCATION_BACKUP,
    DISK_LOCATION_DEFAULT,
    Data_Source,
)
from cve_bin_tool.error_handler import (
    CVEDataForCurlVersionNotInCache,
    ErrorHandler,
    ErrorMode,
)
from cve_bin_tool.log import LOGGER

logging.basicConfig(level=logging.DEBUG)


class Curl_Source(Data_Source):

    SOURCE = "Curl"
    CACHEDIR = DISK_LOCATION_DEFAULT
    BACKUPCACHEDIR = DISK_LOCATION_BACKUP
    LOGGER = LOGGER.getChild("CVEDB")
    CURL_CVE_FILENAME_TEMPLATE = "curlcve-{}.json"

    def __init__(self, error_mode=ErrorMode.TruncTrace):
        self.cve_list = None
        self.cachedir = self.CACHEDIR
        self.backup_cachedir = self.BACKUPCACHEDIR
        self.error_mode = error_mode
        self.session = None
        self.affected_data = None
        self.source_name = self.SOURCE

    async def get_cve_data(self):
        await self.fetch_cves()
        self.get_cve_list()

        return (None, self.affected_data), self.source_name

    async def fetch_cves(self):
        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=19)
            self.session = RateLimiter(
                aiohttp.ClientSession(connector=connector, trust_env=True)
            )

        versions = await self.get_curl_versions(self.session)

        for version in versions:
            await self.download_curl_version(self.session, version)

        await self.session.close()

    @staticmethod
    async def get_curl_versions(session: RateLimiter) -> list[str]:
        regex = re.compile(r"vuln-(\d+.\d+.\d+)\.html")
        async with await session.get(
            "https://curl.haxx.se/docs/vulnerabilities.html"
        ) as response:
            response.raise_for_status()
            html = await response.text()
        matches = regex.finditer(html)
        return [match.group(1) for match in matches]

    async def download_curl_version(self, session: RateLimiter, version: str) -> None:
        async with await session.get(
            f"https://curl.haxx.se/docs/vuln-{version}.html"
        ) as response:
            response.raise_for_status()
            html = await response.text()
        soup = BeautifulSoup(html, "html.parser")
        table = soup.find("table")
        if not table or isinstance(table, NavigableString):
            return
        headers: ResultSet | list = table.find_all("th")
        headers = list(map(lambda x: x.text.strip().lower(), headers))
        self.LOGGER.debug(headers)
        rows = table.find_all("tr")
        json_data = []
        for row in rows:
            cols = row.find_all("td")
            values = (ele.text.strip() for ele in cols)
            data = dict(zip(headers, values))
            if data:
                json_data.append(data)
        path = Path(str(Path(self.cachedir) / f"curlcve-{version}.json"))
        filepath = path.resolve()
        async with FileIO(filepath, "w") as f:
            await f.write(json.dumps(json_data, indent=4))

    def load_curl_version(self, version: str) -> list[dict[str, str]]:
        """
        Return the dict of CVE data for the given curl version.
        """
        filename = Path(
            str(Path(self.cachedir) / self.CURL_CVE_FILENAME_TEMPLATE.format(version))
        )
        # Check if file exists
        if not filename.is_file():
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise CVEDataForCurlVersionNotInCache(version)
        # Open the file and load the JSON data, log the number of CVEs loaded
        with open(filename, "rb") as fileobj:
            cves_for_version = json.load(fileobj)
            self.LOGGER.debug(
                f"Curl Version {version} has {len(cves_for_version)} CVEs in dataset"
            )
            return cves_for_version

    def curl_versions(self) -> list[str]:
        """
        Return the versions we have Curl data for.
        """
        regex = re.compile(r"curlcve-(\d+.\d+.\d).json")
        versions = []
        for filename in glob.glob(str(Path(self.cachedir) / "curlcve-*.json")):
            match = regex.search(filename)
            if match:
                version = match.group(1)
                versions.append(version)
        return versions

    def get_cve_list(self):
        self.affected_data = []

        for version in self.curl_versions():
            cve_list = self.load_curl_version(version)

            for cve in cve_list:
                affected = {
                    "cve_id": cve["cve"],
                    "vendor": "haxx",
                    "product": "curl",
                    "version": version,
                    "versionStartIncluding": cve["from version"],
                    "versionStartExcluding": "",
                    "versionEndIncluding": cve["to and including"],
                    "versionEndExcluding": "",
                }

                self.affected_data.append(affected)

        return self.affected_data
