# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import datetime
import io
import re
import zipfile
from pathlib import Path

import aiohttp
import yaml
from cvss import CVSS2, CVSS3
from yaml.loader import SafeLoader

from cve_bin_tool.async_utils import FileIO, RateLimiter
from cve_bin_tool.data_sources import DISK_LOCATION_DEFAULT, Data_Source
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.log import LOGGER
from cve_bin_tool.version import HTTP_HEADERS


class GAD_Source(Data_Source):
    """Represents a data source for retrieving Common Vulnerabilities and Exposures (CVEs) from GitLab Advisory Database (GAD)."""

    SOURCE = "GAD"
    CACHEDIR = DISK_LOCATION_DEFAULT
    LOGGER = LOGGER.getChild("CVEDB")
    GAD_URL = "https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/archive/master/gemnasium-db-master.zip"
    GAD_COMMIT_URL = "https://gitlab.com/api/v4/projects/12006272/repository/commits"
    GAD_COMPARE_URL = "https://gitlab.com/api/v4/projects/12006272/repository/compare"
    GAD_API_URL = "https://gitlab.com/api/v4/projects/12006272/repository/tree"

    def __init__(
        self, error_mode: ErrorMode = ErrorMode.TruncTrace, incremental_update=False
    ):
        self.cachedir = self.CACHEDIR
        self.slugs = None
        self.gad_path = str(Path(self.cachedir) / "gad")
        self.source_name = self.SOURCE

        self.error_mode = error_mode
        self.incremental_update = incremental_update
        self.time_of_last_update = None

        self.gad_url = self.GAD_URL
        self.gad_commit_url = self.GAD_COMMIT_URL
        self.gad_compare_url = self.GAD_COMPARE_URL
        self.gad_api_url = self.GAD_API_URL
        self.all_cve_entries: list[dict] = []

        self.session = None

    async def update_slugs(self, session):
        """Gets all slug directories that GAD provides."""

        slugs = []

        async with await session.get(self.gad_api_url) as r:
            content = await r.json()

        reject = [".gitlab", "ci"]

        for files in content:
            if files["type"] == "tree" and files["path"] not in reject:
                slugs.append(files["path"])

        self.slugs = slugs

    async def get_slug(self, url, session, mode="json"):
        """Gets slugs or json responses for GitLab API."""

        async with await session.get(url) as r:
            if mode == "bytes":
                content = await r.read()
            else:
                content = await r.json()

        return content

    async def fetch_cves(self):
        """Fetches CVEs from GAD and places them in gad_path."""

        LOGGER.info("Getting GitLab Advisory Database CVEs...")

        from cve_bin_tool import cvedb  # prevent cyclic import

        self.db = cvedb.CVEDB()

        if not Path(self.gad_path).exists():
            Path(self.gad_path).mkdir()
            # As no data, force full update
            self.incremental_update = False

        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=19)
            self.session = RateLimiter(
                aiohttp.ClientSession(
                    connector=connector, headers=HTTP_HEADERS, trust_env=True
                )
            )

        await self.update_slugs(self.session)

        if self.incremental_update and self.db.dbpath.exists():
            time_of_last_update = datetime.datetime.fromtimestamp(
                self.db.get_db_update_date()
            )
            self.time_of_last_update = time_of_last_update
            # get all GAD repository commits since the database was last updated
            url = self.gad_commit_url + "?since=" + str(time_of_last_update)
            content = await self.get_slug(url, self.session)

            if len(content) > 0:
                first_commit_id = content[0]["id"]
                last_commit_id = content[-1]["id"]

                url = (
                    self.gad_compare_url
                    + "?from="
                    + last_commit_id
                    + "&to="
                    + first_commit_id
                )
                content = await self.get_slug(url, self.session)

                # get paths for all the CVE files changed or added
                diff_paths = [
                    x["old_path"] for x in content["diffs"] if ".yml" in x["old_path"]
                ]
            else:
                diff_paths = []

            paths = [x for x in diff_paths if x.split("/")[0] in self.slugs]

        else:
            paths = self.slugs

        tasks = []
        for path in paths:
            url = self.gad_url + "?path=" + path
            task = self.get_slug(url, self.session, mode="bytes")
            tasks.append(task)

        for r in await asyncio.gather(*tasks):
            z = zipfile.ZipFile(io.BytesIO(r))
            z.extractall(self.gad_path)

        await self.session.close()
        self.session = None

    async def update_cve_entries(self):
        """Updates CVE entries from CVEs in cache."""

        p = Path(self.gad_path).glob("**/*")
        # Need to find files which are new to the cache
        last_update_timestamp = (
            self.time_of_last_update.timestamp()
            if self.time_of_last_update is not None
            else 0
        )
        files = [
            x for x in p if x.is_file() and x.stat().st_mtime > last_update_timestamp
        ]
        if len(files) > 0:
            LOGGER.debug(f"Adding {len(files)} GAD entries")
        self.all_cve_entries = []

        for file in files:
            async with FileIO(file, "r", encoding="utf-8") as f:
                r = await f.read()
                data = yaml.load(r, Loader=SafeLoader)

                self.all_cve_entries.append(data)

    def parse_multiple_version(self, range_string):
        """Parses multiple version strings from a range string.
        Args:range_string (str): The range string to parse.
        Returns:list: A list of parsed version strings."""
        version_strings = range_string.split(",")
        start = False
        versions = []
        version = ""
        for version_string in version_strings:
            if version:
                version += ","
            version += version_string
            if "(" in version_string or "[" in version_string:
                start = True
            if start and ("]" in version_string or ")" in version_string):
                versions.append(version)
                version = ""
                start = False

        # For cases like "<1.0.2"
        if version:
            versions.append(version)

        return versions

    def parse_range_string(self, range_string):
        """Parses version strings from GAD CVEs and generates array of version data for affected_data."""
        version_list = []

        version_strings = []
        for version_string in range_string.split("||"):
            version_strings.extend(self.parse_multiple_version(version_string))

        for version_string in version_strings:
            parsed_data = {
                "version": "*",
                "versionStartIncluding": "",
                "versionStartExcluding": "",
                "versionEndIncluding": "",
                "versionEndExcluding": "",
            }

            versions = version_string.replace(",", " ").split(" ")

            for version in versions:
                # Make sure we have an actual version number and not just a bunch of brackets
                if not re.search("[0-9]", version):
                    continue

                # Only a specific version is affected eg. [4.4.0]
                if "[" in version and "]" in version:
                    parsed_data["version"] = version.replace("[", "").replace("]", "")

                elif ">=" in version:
                    parsed_data["versionStartIncluding"] = version.replace(">=", "")
                elif "[" in version:
                    parsed_data["versionStartIncluding"] = version.replace("[", "")

                elif ">" in version:
                    parsed_data["versionStartExcluding"] = version.replace(">", "")
                elif "(" in version:
                    parsed_data["versionStartExcluding"] = version.replace("(", "")

                elif "<=" in version:
                    parsed_data["versionEndIncluding"] = version.replace("<=", "")
                elif "]" in version:
                    parsed_data["versionEndIncluding"] = version.replace("]", "")

                elif "<" in version:
                    parsed_data["versionEndExcluding"] = version.replace("<", "")
                elif ")" in version:
                    parsed_data["versionEndExcluding"] = version.replace(")", "")

                else:
                    parsed_data["version"] = version.replace("=", "")

            version_list.append(parsed_data)

        return version_list

    def format_data(self, all_cve_entries):
        """Formats data from a list of Common Vulnerabilities and Exposures (CVE) entries."""

        severity_data = []
        affected_data = []

        for cve_item in all_cve_entries:
            cve_in_identifier = None

            if not cve_item:
                continue

            for cve in cve_item.get("identifiers"):
                if "CVE" in cve:
                    cve_in_identifier = cve
                    break

            cve_id = (
                cve_in_identifier
                if cve_in_identifier is not None
                else cve_item["identifier"]
            )
            vector = (
                (cve_item["cvss_v3"], 3)
                if cve_item.get("cvss_v3", None)
                else (cve_item.get("cvss_v2", None), 2)
            )

            if vector[0] is not None:
                version = vector[1]

                try:
                    vector = CVSS3(vector[0]) if version == 3 else CVSS2(vector[0])
                    severity = vector.severities()[0]
                    score = vector.scores()[0]

                    vector = vector.clean_vector()
                except Exception as e:
                    LOGGER.debug(e)

                    vector = (None, None)

            cve = {
                "ID": cve_id,
                "severity": severity if vector[0] is not None else "unknown",
                "description": cve_item.get("description", None),
                "score": score if vector[0] is not None else "unknown",
                "CVSS_version": str(version) if vector[0] is not None else "unknown",
                "CVSS_vector": vector if vector[0] is not None else "unknown",
                "last_modified": (
                    cve_item["date"]
                    if cve_item.get("date", None)
                    else cve_item["pubdate"]
                ),
            }

            severity_data.append(cve)

            product = cve_item.get("package_slug").split("/")[-1]
            vendor = "unknown"

            range_string = cve_item.get("affected_range", None)
            parsed_range_data = self.parse_range_string(range_string)

            for range_data in parsed_range_data:
                affected = {
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "product": product,
                    "version": range_data["version"],
                    "versionStartIncluding": range_data["versionStartIncluding"],
                    "versionStartExcluding": range_data["versionStartExcluding"],
                    "versionEndIncluding": range_data["versionEndIncluding"],
                    "versionEndExcluding": range_data["versionEndExcluding"],
                }

                affected_data.append(affected)

        return severity_data, affected_data

    async def get_cve_data(self):
        """Asynchronously fetches and formats Common Vulnerabilities and Exposures (CVE) data."""

        # skip GAD if connection fails
        try:
            await self.fetch_cves()
        except Exception as e:
            LOGGER.debug(f"Error while fetching GitLab Advisory Database CVEs : {e}")
            LOGGER.error("Unable to fetch GitLab Advisory Database CVEs, skipping GAD.")
            if self.session is not None:
                await self.session.close()
            return (list(), list()), self.source_name

        await self.update_cve_entries()

        return self.format_data(self.all_cve_entries), self.source_name
