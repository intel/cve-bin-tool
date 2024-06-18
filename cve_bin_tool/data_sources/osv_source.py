# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import datetime
import io
import json
import zipfile
from pathlib import Path

import aiohttp
from cvss import CVSS3

from cve_bin_tool.async_utils import FileIO, RateLimiter, aio_run_command
from cve_bin_tool.data_sources import DISK_LOCATION_DEFAULT, Data_Source
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.log import LOGGER
from cve_bin_tool.version import HTTP_HEADERS


class OSV_Source(Data_Source):
    """Class to retrieve CVE's from the Open Source Vulnerabilities (OSV) Database"""

    SOURCE = "OSV"
    CACHEDIR = DISK_LOCATION_DEFAULT
    LOGGER = LOGGER.getChild("CVEDB")
    OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/"
    OSV_GS_URL = "gs://osv-vulnerabilities/"

    def __init__(
        self, error_mode: ErrorMode = ErrorMode.TruncTrace, incremental_update=False
    ):
        self.cachedir = self.CACHEDIR
        self.ecosystems = None
        self.osv_path = str(Path(self.cachedir) / "osv")
        self.source_name = self.SOURCE

        self.error_mode = error_mode
        self.incremental_update = incremental_update
        self.time_of_last_update = None
        self.incremental_threshold = 30

        self.osv_url = self.OSV_URL
        self.gs_url = self.OSV_GS_URL
        self.all_cve_entries: list[dict] = []

        self.session = None

    async def update_ecosystems(self):
        """Gets names of all ecosystems that OSV provides."""

        ecosystems = []

        # Inspect the list of files and folders at the top level in the GS bucket.
        stdout, _, _ = await aio_run_command(["gsutil", "ls", self.gs_url])
        lines = stdout.split(b"\n")

        # For each line in the directory listing determine if it is a folder that
        # contains all.zip.
        for line in lines:
            ecosystem_zip = line + b"all.zip"
            stdout, _, _ = await aio_run_command(["gsutil", "ls", ecosystem_zip])
            if stdout.strip(b"\n") == ecosystem_zip:
                # Found a valid ecosystem
                ecosystem = str(line).split("/")[-2]
                ecosystems.append(ecosystem)

        self.ecosystems = ecosystems

    async def get_ecosystem(self, ecosystem_url, session, mode="json"):
        """Fetches either a specific CVE or all.zip(containing all CVEs) file from an ecosystem."""

        async with await session.get(ecosystem_url) as r:
            if mode == "bytes":
                content = await r.read()
            else:
                content = await r.json()
            return content

    async def get_ecosystem_incremental(self, ecosystem, time_of_last_update, session):
        """Fetches list of new CVEs and uses get_ecosystem to get them, if CVEs are greater than threshold value returns just the name of ecosystem."""

        newfiles = await self.get_newfiles(ecosystem, time_of_last_update)

        # skip ecosystem if there are too many individual CVEs to download
        if len(newfiles) > self.incremental_threshold:
            return ecosystem

        # Check if anything to process
        if len(newfiles) == 0:
            return None

        tasks = []

        for file in newfiles:
            eco_url = self.osv_url + ecosystem + "/" + file
            task = self.get_ecosystem(eco_url, session)
            tasks.append(task)

        for r in await asyncio.gather(*tasks):
            filepath = Path(self.osv_path) / (r.get("id") + ".json")
            r = json.dumps(r)

            async with FileIO(filepath, "w") as f:
                await f.write(r)

        return None

    def parse_filename(self, str):
        """Parses the filename of a JSON in the OSV GS bucket after the JSON
        extension has been stripped off to extract the filename and timestamp."""
        str = str.split("  ")

        filename = str[-1]

        if "zip" in filename:
            return None, None

        filename = filename.split("/")[-1] + "json"
        timestamp = datetime.datetime.strptime(str[-2], "%Y-%m-%dT%H:%M:%SZ")

        return filename, timestamp

    async def get_newfiles(self, ecosystem, time_of_last_update):
        """Gets list of files modified after time of last update."""

        gs_file = self.gs_url + ecosystem
        stdout, _, _ = await aio_run_command(["gsutil", "ls", "-l", gs_file])
        stdout = str(stdout).split("json")

        newfiles = []

        for line in stdout:
            filename, timestamp = self.parse_filename(line)
            if timestamp is not None and timestamp > time_of_last_update:
                newfiles.append(filename)

        return newfiles

    async def get_totalfiles(self, ecosystem):
        """Gets total number of files in an ecosystem"""

        gs_file = self.gs_url + ecosystem + "/all.zip"
        await aio_run_command(["gsutil", "cp", gs_file, self.osv_path])

        zip_path = Path(self.osv_path) / "all.zip"
        totalfiles = 0

        with zipfile.ZipFile(zip_path, "r") as z:
            files = z.namelist()
            totalfiles = len(files)

        zip_path.unlink()
        return totalfiles

    async def fetch_cves(self):
        """Fetches CVEs from OSV and places them in osv_path."""

        LOGGER.info("Getting Open Source Vulnerability Database CVEs...")

        from cve_bin_tool import cvedb  # prevent cyclic import

        self.db = cvedb.CVEDB()

        if not Path(self.osv_path).exists():
            Path(self.osv_path).mkdir()
            # As no data, force full update
            self.incremental_update = False

        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=19)
            self.session = RateLimiter(
                aiohttp.ClientSession(
                    connector=connector, headers=HTTP_HEADERS, trust_env=True
                )
            )

        if self.incremental_update and self.db.dbpath.exists():
            # check if all CVE files in ecosystem are modified
            time_of_last_update = datetime.datetime.fromtimestamp(
                self.db.get_db_update_date()
            )
            self.time_of_last_update = time_of_last_update
            newfiles = await self.get_newfiles(self.ecosystems[0], time_of_last_update)
            totalfiles = await self.get_totalfiles(self.ecosystems[0])

            # if all CVE files are modified all.zip should be downloaded
            if len(newfiles) == totalfiles:
                self.incremental_update = False

        # ecosystems to download all.zip for if CVEs are greater than threshold or incremental update is false
        ecosystems = [] if self.incremental_update else self.ecosystems

        if self.incremental_update and self.db.dbpath.exists():
            tasks = []
            for ecosystem in self.ecosystems:
                task = self.get_ecosystem_incremental(
                    ecosystem, time_of_last_update, self.session
                )

                tasks.append(task)

            for skipped_ecosystem in await asyncio.gather(*tasks):
                if skipped_ecosystem:
                    ecosystems.append(skipped_ecosystem)

        if len(ecosystems) > 0:
            tasks = []
            for ecosystem in ecosystems:
                eco_url = self.osv_url + ecosystem + "/all.zip"
                task = self.get_ecosystem(eco_url, self.session, mode="bytes")

                tasks.append(task)

            for r in await asyncio.gather(*tasks):
                z = zipfile.ZipFile(io.BytesIO(r))
                z.extractall(self.osv_path)

        await self.session.close()
        self.session = None

    async def update_cve_entries(self):
        """Updates CVE entries from CVEs in cache"""

        p = Path(self.osv_path).glob("**/*")
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
            LOGGER.debug(f"Adding {len(files)} OSV entries")
        self.all_cve_entries = []

        for file in files:
            async with FileIO(file, "r", encoding="utf-8") as f:
                r = await f.read()
                data = json.loads(r)

                self.all_cve_entries.append(data)

    def format_data(self, all_cve_entries):
        """Format the CVE entries from the OSV schema into a format for CVEDB."""
        severity_data = []
        affected_data = []

        for cve_item in all_cve_entries:
            cve_id = cve_item["id"]
            severity = cve_item.get("severity", None)
            vector = None

            # getting score
            # OSV Schema currently only provides CVSS V3 scores, though more scores may be added in the future
            if severity is not None and "CVSS_V3" in [x["type"] for x in severity]:
                try:
                    # Ensure CVSS vector is valid
                    if severity[0]["score"].endswith("/"):
                        cvss_data = CVSS3(severity[0]["score"][:-1])
                        LOGGER.debug(f"{cve_id} : Correcting malformed CVSS3 vector")
                    else:
                        cvss_data = CVSS3(severity[0]["score"])
                    # Now extract CVSS attributes
                    version = "3"
                    severity = cvss_data.severities()[0]
                    score = cvss_data.scores()[0]
                    vector = cvss_data.clean_vector()

                except Exception as e:
                    LOGGER.debug(e)
                    LOGGER.debug(f"{cve_id} : {severity}")
                    vector = None

            cve = {
                "ID": cve_id,
                "severity": severity if vector is not None else "unknown",
                "description": cve_item.get("summary", "unknown"),
                "score": score if vector is not None else "unknown",
                "CVSS_version": version if vector is not None else "unknown",
                "CVSS_vector": vector if vector is not None else "unknown",
                "last_modified": (
                    cve_item["modified"]
                    if cve_item.get("modified", None)
                    else cve_item["published"]
                ),
            }

            severity_data.append(cve)

            for package_data in cve_item.get("affected", []):
                package = package_data.get("package", {})
                if not package:
                    continue

                product = package.get("name")
                vendor = (
                    "unknown"  # OSV Schema does not provide vendor names for packages
                )

                if product.startswith("github.com/"):
                    vendor = product.split("/")[-2]
                    product = product.split("/")[-1]

                affected = {
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "product": product,
                    "version": "*",
                    "versionStartIncluding": "",
                    "versionStartExcluding": "",
                    "versionEndIncluding": "",
                    "versionEndExcluding": "",
                }

                events = None
                for ranges in package_data.get("ranges", []):
                    if ranges["type"] == "SEMVER":
                        events = ranges["events"]

                if events is None and "versions" in package_data:
                    versions = package_data["versions"]

                    if versions == []:
                        continue

                    version_affected = affected.copy()

                    version_affected["versionStartIncluding"] = versions[0]
                    version_affected["versionEndIncluding"] = versions[-1]

                    affected_data.append(version_affected)
                elif events is not None:
                    introduced = None
                    fixed = None

                    for event in events:
                        if event.get("introduced", None):
                            introduced = event.get("introduced")
                        if event.get("fixed", None):
                            fixed = event.get("fixed")

                        if fixed is not None:
                            range_affected = affected.copy()

                            range_affected["versionStartIncluding"] = introduced
                            range_affected["versionEndExcluding"] = fixed

                            fixed = None

                            affected_data.append(range_affected)

        return severity_data, affected_data

    async def get_cve_data(self):
        """Update the OSV CVE's and return the formatted data of all OSV CVE's."""
        await self.update_ecosystems()

        # skip OSV if connection fails
        try:
            await self.fetch_cves()
        except Exception as e:
            LOGGER.debug(f"Error while fetching OSV CVEs : {e}")
            LOGGER.error("Unable to fetch OSV CVEs, skipping OSV.")
            if self.session is not None:
                await self.session.close()
            return (list(), list()), self.source_name

        await self.update_cve_entries()

        return self.format_data(self.all_cve_entries), self.source_name
