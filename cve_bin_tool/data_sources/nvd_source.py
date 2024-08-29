# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import datetime
import glob
import gzip
import hashlib
import json
import logging
import re
import sqlite3
from pathlib import Path

import aiohttp
from rich.progress import track

from cve_bin_tool.async_utils import FileIO, GzipFile, RateLimiter
from cve_bin_tool.data_sources import (
    DBNAME,
    DISK_LOCATION_BACKUP,
    DISK_LOCATION_DEFAULT,
    NVD_FILENAME_TEMPLATE,
    Data_Source,
)
from cve_bin_tool.error_handler import (
    AttemptedToWriteOutsideCachedir,
    CVEDataForYearNotInCache,
    ErrorHandler,
    ErrorMode,
    NVDRateLimit,
    SHAMismatch,
)
from cve_bin_tool.log import LOGGER
from cve_bin_tool.nvd_api import NVD_API
from cve_bin_tool.version import HTTP_HEADERS

logging.basicConfig(level=logging.DEBUG)


class NVD_Source(Data_Source):
    """
    Downloads NVD data in json form and stores it on disk in a cache.
    """

    SOURCE = "NVD"
    CACHEDIR = DISK_LOCATION_DEFAULT
    BACKUPCACHEDIR = DISK_LOCATION_BACKUP
    FEED_NVD = "https://nvd.nist.gov/vuln/data-feeds"
    FEED_MIRROR = "https://mirror.cveb.in/nvd/json/cve/1.1"
    LOGGER = LOGGER.getChild("CVEDB")
    NVDCVE_FILENAME_TEMPLATE = NVD_FILENAME_TEMPLATE
    META_LINK_NVD = "https://nvd.nist.gov"
    META_LINK_MIRROR = "https://mirror.cveb.in/nvd/json/cve/1.1"
    META_REGEX_NVD = re.compile(r"feeds\/json\/.*-[0-9]*\.[0-9]*-[0-9]*\.meta")
    META_REGEX_MIRROR = re.compile(r"nvdcve-[0-9]*\.[0-9]*-[0-9]*\.meta")
    RANGE_UNSET = ""

    def __init__(
        self,
        feed: str | None = None,
        session: RateLimiter | None = None,
        error_mode: ErrorMode = ErrorMode.TruncTrace,
        nvd_type: str = "json-mirror",
        incremental_update: bool = False,
        nvd_api_key: str = "",
    ):
        if feed is None:
            self.feed = self.FEED_NVD if nvd_type == "json-nvd" else self.FEED_MIRROR
        else:
            self.feed = feed
        self.cachedir = self.CACHEDIR
        self.backup_cachedir = self.BACKUPCACHEDIR
        self.error_mode = error_mode
        self.source_name = self.SOURCE

        # set up the db if needed
        self.dbpath = str(Path(self.cachedir) / DBNAME)
        self.connection: sqlite3.Connection | None = None
        self.session = session
        self.cve_count = -1
        self.nvd_type = nvd_type
        self.incremental_update = incremental_update
        self.all_cve_entries: list[dict[str, object]] | None = None

        # store the nvd api key for use later
        self.nvd_api_key = nvd_api_key

        # if nvd_api_key was set to "No" then unset it
        # This makes it easier to disable usage from the command line
        # and over-riding existing environment variables.
        if self.nvd_api_key.lower() == "no":
            self.nvd_api_key = ""
            LOGGER.info("NVD API Key was set to 'no' and will not be used")

    async def get_cve_data(self):
        """Retrieves the CVE data from the data source."""
        await self.fetch_cves()

        if self.nvd_type == "api2":
            return self.format_data_api2(self.all_cve_entries), self.source_name

        else:
            severity_data = []
            affected_data = []
            years = self.nvd_years()
            for year in years:
                severity, affected = self.format_data(
                    self.load_nvd_year(year)["CVE_Items"]
                )
                severity_data.extend(severity)
                affected_data.extend(affected)

            return (severity_data, affected_data), self.source_name

    def format_data(self, all_cve_entries):
        """Format CVE data for CVEDB"""

        cve_data = []
        affects_data = []

        for cve_item in all_cve_entries:
            # the information we want:
            # CVE ID, Severity, Score ->
            # affected {Vendor(s), Product(s), Version(s)}

            cve = {
                "ID": cve_item["cve"]["CVE_data_meta"]["ID"],
                "description": cve_item["cve"]["description"]["description_data"][0][
                    "value"
                ],
                "severity": "unknown",
                "score": "unknown",
                "CVSS_version": "unknown",
                "CVSS_vector": "unknown",
                "last_modified": (
                    cve_item["lastModifiedDate"]
                    if cve_item.get("lastModifiedDate", None)
                    else cve_item["publishedDate"]
                ),
            }
            if cve["description"].startswith("** REJECT **"):
                # Skip this CVE if it's marked as 'REJECT'
                continue

            # Get CVSSv3 or CVSSv2 score for output.
            # Details are left as an exercise to the user.
            if "baseMetricV3" in cve_item["impact"]:
                cve["severity"] = cve_item["impact"]["baseMetricV3"]["cvssV3"][
                    "baseSeverity"
                ]
                cve["score"] = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                cve["CVSS_vector"] = cve_item["impact"]["baseMetricV3"]["cvssV3"][
                    "vectorString"
                ]
                cve["CVSS_version"] = 3
            elif "baseMetricV2" in cve_item["impact"]:
                cve["severity"] = cve_item["impact"]["baseMetricV2"]["severity"]
                cve["score"] = cve_item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                cve["CVSS_vector"] = cve_item["impact"]["baseMetricV2"]["cvssV2"][
                    "vectorString"
                ]
                cve["CVSS_version"] = 2

            # Ensure score is valid field
            cve["score"] = cve["score"] if cve["score"] is not None else "unknown"
            cve_data.append(cve)

            # walk the nodes with version data
            # return list of versions
            affects_list = []
            if "configurations" in cve_item:
                for node in cve_item["configurations"]["nodes"]:
                    affects_list.extend(self.parse_node(node))
                    if "children" in node:
                        for child in node["children"]:
                            affects_list.extend(self.parse_node(child))

            for affects in affects_list:
                affects["cve_id"] = cve["ID"]

            affects_data.extend(affects_list)

        return cve_data, affects_data

    def parse_node(self, node: dict[str, list[dict[str, str]]]) -> list[dict[str, str]]:
        affects_list = []
        if "cpe_match" in node:
            vulnerable_matches = (m for m in node["cpe_match"] if m["vulnerable"])
            for cpe_match in vulnerable_matches:
                # split on `:` only if it's not escaped
                cpe_split = re.split(r"(?<!\\):", cpe_match["cpe23Uri"])
                affects = {
                    "vendor": cpe_split[3],
                    "product": cpe_split[4],
                    "version": cpe_split[5],
                }

                # if we have a range (e.g. version is *) fill it out, and put blanks where needed
                range_fields = [
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                ]
                for field in range_fields:
                    if field in cpe_match:
                        affects[field] = cpe_match[field]
                    else:
                        affects[field] = self.RANGE_UNSET

                affects_list.append(affects)
        return affects_list

    def format_data_api2(self, all_cve_entries):
        """Format CVE data for CVEDB"""

        cve_data = []
        affects_data = []

        self.LOGGER.debug(f"Process vuln data - {len(all_cve_entries)} entries")

        for cve_element in all_cve_entries:
            # the information we want:
            # CVE ID, Severity, Score ->
            # affected {Vendor(s), Product(s), Version(s)}

            cve_item = cve_element["cve"]

            cve = {
                "ID": cve_item["id"],
                "description": cve_item["descriptions"][0]["value"],
                "severity": "unknown",
                "score": "unknown",
                "CVSS_version": "unknown",
                "CVSS_vector": "unknown",
                "last_modified": (
                    cve_item["lastModified"]
                    if cve_item.get("lastModified", None)
                    else cve_item["published"]
                ),
            }
            if cve["description"].startswith("** REJECT **"):
                # Skip this CVE if it's marked as 'REJECT'
                continue

            # Multiple ways of including CVSS metrics.
            # Newer data uses "impact" -- we may wish to delete the old below

            # sometimes (frequently?) the impact is empty
            if "impact" in cve_item:
                if "baseMetricV3" in cve_item["impact"]:
                    cve["CVSS_version"] = 3
                    if "cvssV3" in cve_item["impact"]["baseMetricV3"]:
                        # grab either the data or some default values
                        cve["severity"] = cve_item["impact"]["baseMetricV3"][
                            "cvssV3"
                        ].get("baseSeverity", "UNKNOWN")
                        cve["score"] = cve_item["impact"]["baseMetricV3"]["cvssV3"].get(
                            "baseScore", 0
                        )
                        cve["CVSS_vector"] = cve_item["impact"]["baseMetricV3"][
                            "cvssV3"
                        ].get("vectorString", "")

                # severity is in a different spot in v2 versus v3
                elif "baseMetricV2" in cve_item["impact"]:
                    cve["CVSS_version"] = 2
                    cve["severity"] = cve_item["impact"]["baseMetricV4"].get(
                        "severity", "UNKNOWN"
                    )
                    if "cvssV2" in cve_item["impact"]["baseMetricV2"]:
                        cve["score"] = cve_item["impact"]["baseMetricV2"]["cvssV2"].get(
                            "baseScore", 0
                        )
                        cve["CVSS_vector"] = cve_item["impact"]["baseMetricV2"][
                            "cvssV2"
                        ].get("vectorString", "")

            # Old data used "metrics" -- This section may need to be deleted
            elif "metrics" in cve_item:
                cve_cvss = cve_item["metrics"]

                # Get CVSSv3 or CVSSv2 score
                cvss_available = True
                if "cvssMetricV31" in cve_cvss:
                    cvss_data = cve_cvss["cvssMetricV31"][0]["cvssData"]
                    cve["CVSS_version"] = 3
                elif "cvssMetricV30" in cve_cvss:
                    cvss_data = cve_cvss["cvssMetricV30"][0]["cvssData"]
                    cve["CVSS_version"] = 3
                elif "cvssMetricV2" in cve_cvss:
                    cvss_data = cve_cvss["cvssMetricV2"][0]["cvssData"]
                    cve["CVSS_version"] = 2
                else:
                    cvss_available = False
                if cvss_available:
                    cve["severity"] = cvss_data.get("baseSeverity", "UNKNOWN")
                    cve["score"] = cvss_data.get("baseScore", 0)
                    cve["CVSS_vector"] = cvss_data.get("vectorString", "")
            # End old metrics  section

            # do some basic input validation checks
            # severity should be alphanumeric
            if not cve["severity"].isalnum():
                self.logger.debug(
                    f"Severity for {cve['id']} is invalid: {cve['severity']}"
                )
                cve["severity"] = re.sub(r"[\W]", "", cve["severity"])

            # score should be numeric
            try:
                cve["score"] = float(cve["score"])
            except ValueError:
                self.logger.debug(f"Score for {cve['id']} is invalid: {cve['score']}")
                cve["score"] = "invalid"

            # CVSS_vector will be validated/normalized when cvss library is used but
            # we can at least do a character filter here
            # we expect letters (mostly but not always uppercase), numbers,  : and /
            cve["CVSS_vector"] = re.sub("[^A-Za-z0-9:/]", "", cve["CVSS_vector"])

            cve_data.append(cve)

            # walk the nodes with version data
            # return list of versions
            affects_list = []
            if "configurations" in cve_item:
                for configuration in cve_item["configurations"]:
                    for node in configuration["nodes"]:
                        self.LOGGER.debug(f"Processing {node} for {cve_item['id']}")
                        affects_list.extend(self.parse_node_api2(node))
                        if "children" in node:
                            for child in node["children"]:
                                affects_list.extend(self.parse_node_api2(child))
            else:
                LOGGER.debug(f"No configuration information for {cve_item['id']}")
            for affects in affects_list:
                affects["cve_id"] = cve["ID"]

            affects_data.extend(affects_list)

        return cve_data, affects_data

    def parse_node_api2(
        self, node: dict[str, list[dict[str, str]]]
    ) -> list[dict[str, str]]:
        affects_list = []
        if "cpeMatch" in node:
            vulnerable_matches = (m for m in node["cpeMatch"] if m["vulnerable"])
            for cpe_match in vulnerable_matches:
                # split on `:` only if it's not escaped
                cpe_split = re.split(r"(?<!\\):", cpe_match["criteria"])
                affects = {
                    "vendor": cpe_split[3],
                    "product": cpe_split[4],
                    "version": cpe_split[5],
                }

                # if we have a range (e.g. version is *) fill it out, and put blanks where needed
                range_fields = [
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                ]
                for field in range_fields:
                    if field in cpe_match:
                        affects[field] = cpe_match[field]
                    else:
                        affects[field] = self.RANGE_UNSET

                affects_list.append(affects)
        return affects_list

    async def fetch_cves(self):
        """Fetches CVEs from the NVD data source."""
        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=19)
            self.session = RateLimiter(
                aiohttp.ClientSession(
                    connector=connector, headers=HTTP_HEADERS, trust_env=True
                )
            )

        tasks = []
        LOGGER.info("Getting NVD CVE data...")
        if self.nvd_type == "api2":
            self.all_cve_entries = await asyncio.create_task(
                self.nist_fetch_using_api(),
            )
        else:
            nvd_metadata = await asyncio.create_task(
                self.nist_scrape(self.session),
            )

            tasks = [
                self.cache_update(self.session, url, meta["sha256"])
                for url, meta in nvd_metadata.items()
                if meta is not None
            ]

        total_tasks = len(tasks)

        # error_mode.value will only be greater than 1 if quiet mode.
        if self.error_mode.value > 1 and self.nvd_type.startswith("json"):
            iter_tasks = track(
                asyncio.as_completed(tasks),
                description="Downloading CVEs...",
                total=total_tasks,
            )
        else:
            iter_tasks = asyncio.as_completed(tasks)

        for task in iter_tasks:
            await task

        await self.session.close()
        self.session = None

    async def nist_fetch_using_api(self) -> list:
        """Fetch using NVD's CVE API (as opposed to NVD's JSON Vulnerability Feeds)"""

        from cve_bin_tool import cvedb  # prevent cyclic import

        db = cvedb.CVEDB()

        if self.nvd_type == "api2":
            LOGGER.info("[Using NVD API 2.0]")
            api_version = "2.0"

        # Can only do incremental update if database exists
        if not db.dbpath.exists():
            # Disable incremental update because database doesn't exist
            self.incremental_update = False

        nvd_api = NVD_API(
            logger=self.LOGGER,
            error_mode=self.error_mode,
            incremental_update=self.incremental_update,
            api_key=self.nvd_api_key,
            api_version=api_version,
        )
        if self.incremental_update:
            await nvd_api.get_nvd_params(
                time_of_last_update=datetime.datetime.fromtimestamp(
                    db.get_db_update_date()
                )
            )
        else:
            await nvd_api.get_nvd_params()
        await nvd_api.get()
        await nvd_api.session.close()
        nvd_api.session = None
        return nvd_api.all_cve_entries

    async def getmeta(
        self, session: RateLimiter, meta_url: str
    ) -> tuple[str, dict[str, str]]:
        async with await session.get(meta_url) as response:
            response.raise_for_status()
            return (
                meta_url.replace(".meta", ".json.gz"),
                dict(
                    [
                        line.split(":", maxsplit=1)
                        for line in (await response.text()).splitlines()
                        if ":" in line
                    ]
                ),
            )

    async def nist_scrape(self, session: RateLimiter):
        async with await session.get(self.feed) as response:
            response.raise_for_status()
            page = await response.text()
            if self.nvd_type == "json-nvd":
                json_meta_links = self.META_REGEX_NVD.findall(page)
                meta_host = self.META_LINK_NVD
            else:
                json_meta_links = self.META_REGEX_MIRROR.findall(page)
                meta_host = self.META_LINK_MIRROR
            return dict(
                await asyncio.gather(
                    *(
                        self.getmeta(session, f"{meta_host}/{meta_url}")
                        for meta_url in json_meta_links
                    )
                )
            )

    async def cache_update(
        self,
        session: RateLimiter,
        url: str,
        sha: str,
        chunk_size: int = 16 * 1024,
    ) -> None:
        """
        Update the cache for a single year of NVD data.
        """
        filename = url.split("/")[-1]
        # Ensure we only write to files within the cachedir
        cache_path = Path(self.cachedir)
        filepath = Path(str(cache_path / filename)).resolve()
        if not str(filepath).startswith(str(cache_path.resolve())):
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise AttemptedToWriteOutsideCachedir(filepath)
        # Validate the contents of the cached file
        if filepath.is_file():
            # Validate the sha and write out
            sha = sha.upper()
            calculate = hashlib.sha256()
            async with GzipFile(filepath, "rb") as f:
                chunk = await f.read(chunk_size)
                while chunk:
                    calculate.update(chunk)
                    chunk = await f.read(chunk_size)
            # Validate the sha and exit if it is correct, otherwise update
            gotsha = calculate.hexdigest().upper()
            if gotsha != sha:
                filepath.unlink()
                self.LOGGER.debug(
                    f"SHA mismatch for {filename} (have: {gotsha}, want: {sha})"
                )
            else:
                self.LOGGER.debug(f"Correct SHA for {filename}")
                return
        self.LOGGER.debug(f"Updating CVE cache for {filename}")
        async with await session.get(url) as response:
            # Raise better error message on ratelimit by NVD
            if response.status == 403:
                with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                    raise NVDRateLimit(
                        f"{url} : download failed, you may have been rate limited."
                    )
            # Raise for all other 4xx errors
            response.raise_for_status()
            gzip_data = await response.read()
        json_data = gzip.decompress(gzip_data)
        gotsha = hashlib.sha256(json_data).hexdigest().upper()
        async with FileIO(filepath, "wb") as filepath_handle:
            await filepath_handle.write(gzip_data)
        # Raise error if there was an issue with the sha
        if gotsha != sha:
            # Remove the file if there was an issue
            # exit(100)
            filepath.unlink()
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise SHAMismatch(f"{url} (have: {gotsha}, want: {sha})")

    def load_nvd_year(self, year: int) -> dict[str, str | object]:
        """
        Return the dict of CVE data for the given year.
        """

        filename = Path(self.cachedir) / self.NVDCVE_FILENAME_TEMPLATE.format(year)
        # Check if file exists
        if not filename.is_file():
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise CVEDataForYearNotInCache(year)
        # Open the file and load the JSON data, log the number of CVEs loaded
        with gzip.open(filename, "rb") as fileobj:
            cves_for_year = json.load(fileobj)
            self.LOGGER.debug(
                f'Year {year} has {len(cves_for_year["CVE_Items"])} CVEs in dataset'
            )
            return cves_for_year

    def nvd_years(self) -> list[int]:
        """
        Return the years we have NVD data for.
        """
        return sorted(
            int(filename.split(".")[-3].split("-")[-1])
            for filename in glob.glob(str(Path(self.cachedir) / "nvdcve-1.1-*.json.gz"))
        )
