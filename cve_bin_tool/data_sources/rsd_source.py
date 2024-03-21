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
from cvss import CVSS2, CVSS3

from cve_bin_tool.async_utils import FileIO, RateLimiter
from cve_bin_tool.data_sources import DISK_LOCATION_DEFAULT, Data_Source
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.log import LOGGER
from cve_bin_tool.version import HTTP_HEADERS


class RSD_Source(Data_Source):
    """Data source for fetching CVE data from RedHat Security Database."""

    SOURCE = "RSD"
    CACHEDIR = DISK_LOCATION_DEFAULT
    LOGGER = LOGGER.getChild("CVEDB")
    RSD_URL = "https://gitlab.com/vulnerabilities1/vulnerabities/-/archive/main/vulnerabities-main.zip"
    RSD_COMMIT_URL = "https://gitlab.com/api/v4/projects/39314828/repository/commits"
    RSD_COMPARE_URL = "https://gitlab.com/api/v4/projects/39314828/repository/compare"
    RSD_API_URL = "https://gitlab.com/api/v4/projects/39314828/repository/tree"

    def __init__(
        self, error_mode: ErrorMode = ErrorMode.TruncTrace, incremental_update=False
    ):
        self.cachedir = self.CACHEDIR
        self.rsd_path = str(Path(self.cachedir) / "rsd")
        self.source_name = self.SOURCE

        self.error_mode = error_mode
        self.incremental_update = incremental_update
        self.time_of_last_update = None

        self.rsd_url = self.RSD_URL
        self.rsd_commit_url = self.RSD_COMMIT_URL
        self.rsd_compare_url = self.RSD_COMPARE_URL
        self.rsd_api_url = self.RSD_API_URL
        self.all_cve_entries: list[dict] = []

        self.session = None

    async def get_req(self, url, session, mode="json"):
        """Gets CVEs directory or json responses for GitLab API."""

        async with await session.get(url) as r:
            if mode == "bytes":
                content = await r.read()
            else:
                content = await r.json()

        return content

    async def fetch_cves(self):
        """Fetches CVEs from RedHat Security Database and places them in rsd_path."""

        LOGGER.info("Getting RedHat Security Database CVEs...")

        from cve_bin_tool import cvedb  # prevent cyclic import

        self.db = cvedb.CVEDB()

        if not Path(self.rsd_path).exists():
            Path(self.rsd_path).mkdir()

        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=19)
            self.session = RateLimiter(
                aiohttp.ClientSession(
                    connector=connector, headers=HTTP_HEADERS, trust_env=True
                )
            )

        if self.incremental_update and self.db.dbpath.exists():
            time_of_last_update = datetime.datetime.fromtimestamp(
                self.db.get_db_update_date()
            )
            self.time_of_last_update = time_of_last_update

            # get all RSD repository commits since the database was last updated
            url = self.rsd_commit_url + "?since=" + str(time_of_last_update)
            content = await self.get_req(url, self.session)

            if len(content) > 0:
                first_commit_id = content[0]["id"]
                last_commit_id = content[-1]["id"]

                url = (
                    self.rsd_compare_url
                    + "?from="
                    + last_commit_id
                    + "&to="
                    + first_commit_id
                )
                content = await self.get_req(url, self.session)

                # get paths for all the CVE files changed or added
                diff_paths = [
                    x["old_path"] for x in content["diffs"] if ".json" in x["old_path"]
                ]
            else:
                diff_paths = []

            paths = [x for x in diff_paths if x.split("/")[0] == "redhat"]

        else:
            paths = ["redhat"]

        tasks = []
        for path in paths:
            url = self.rsd_url + "?path=" + path
            task = self.get_req(url, self.session, mode="bytes")
            tasks.append(task)

        for r in await asyncio.gather(*tasks):
            z = zipfile.ZipFile(io.BytesIO(r))
            z.extractall(self.rsd_path)

        await self.session.close()
        self.session = None

    async def update_cve_entries(self):
        """Updates CVE entries from CVEs in cache."""

        p = Path(self.rsd_path).glob("**/*")
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
            LOGGER.debug(f"Adding {len(files)} RSD entries")
        self.all_cve_entries = []

        for file in files:
            async with FileIO(file, "r", encoding="utf-8") as f:
                r = await f.read()
                data = json.loads(r)

                self.all_cve_entries.append(data)

    def format_data(self, all_cve_entries):
        """
        Reformats RedHat Security Database CVE data

            Parameters:
                all_cve_entries (any): An iterable of CVE entries from RedHat Security Database

            Returns:
                severity_data (list): CVE entries with associated severity data
                affected_data (list): CVE entries with associated affected package data
        """
        severity_data = []
        affected_data = []

        for cve_item in all_cve_entries:
            if cve_item.get("package_state", None) is None:
                continue

            cve_id = cve_item["name"]

            vector = (
                (cve_item["cvss3"]["cvss3_scoring_vector"], 3)
                if cve_item["cvss3"].get("cvss3_scoring_vector", None) == ""
                else (
                    cve_item.get("cvss", {"cvss_scoring_vector": ""}).get(
                        "cvss_scoring_vector", None
                    ),
                    2,
                )
            )

            if len(vector[0]) > 0:
                version = vector[1]
                # Ensure CVSS vector is valid
                if vector[0].endswith("/"):
                    LOGGER.debug(
                        f"{cve_id} : Correcting malformed CVSS3 vector {vector[0]}"
                    )
                    vector[0] = vector[0][:-1]
                try:
                    vector = CVSS3(vector[0]) if version == 3 else CVSS2(vector[0])
                    severity = vector.severities()[0]
                    # Score already provided
                    score = (
                        cve_item["cvss3"]["cvss3_base_score"]
                        if version == 3
                        else cve_item["cvss"]["cvss_base_score"]
                    )
                    vector = vector.clean_vector()
                except Exception as e:
                    LOGGER.debug(f"Error processing CVSS vector for {cve_id} : {e}")
                    vector = (None, None)
            else:
                vector = (None, None)

            cve = {
                "ID": cve_id,
                "severity": severity if vector[0] is not None else "unknown",
                "description": cve_item.get("details", "unknown"),
                "score": score if vector[0] is not None else "unknown",
                "CVSS_version": str(version) if vector[0] is not None else "unknown",
                "CVSS_vector": vector if vector[0] is not None else "unknown",
                "last_modified": cve_item["public_date"],
            }

            severity_data.append(cve)

            p_states = cve_item["package_state"]

            for state in p_states:
                cpe = state["cpe"]
                cpe = cpe.split(":")

                fix_state = state["fix_state"]

                if fix_state == "Not affected":
                    continue

                try:
                    if len(cpe) < 5:
                        # Sometimes vendor not specified
                        if cpe[2] != "redhat":
                            # Vendor not specified, so assume this is a RedHat product
                            vendor = "redhat"
                            product = cpe[2]
                            version = cpe[3]
                            LOGGER.debug(
                                f"{cve_id} : Correcting malformed cpe string for {product}"
                            )
                        else:
                            # Vendor specified but some other data missing
                            continue
                    else:
                        vendor = cpe[2]
                        product = cpe[3]
                        version = cpe[4]
                except Exception as e:
                    LOGGER.debug(e)
                    LOGGER.debug(f'{cve_id} {state["cpe"]} {cpe}')
                    continue

                affected = {
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "product": product,
                    "version": version,
                    "versionStartIncluding": "",
                    "versionStartExcluding": "",
                    "versionEndIncluding": "",
                    "versionEndExcluding": "",
                }

                affected_data.append(affected)

        return severity_data, affected_data

    async def get_cve_data(self):
        """
        Fetches RedHat Security Database CVEs, updates entries, and returns formatted data
        along with the source name.

        Returns:
            self.format_data(self.cve_entries) (tuple[list, list]): Formatted CVE data
            self.source_name (str): Name of CVE source
        """
        # skip RSD if connection fails
        try:
            await self.fetch_cves()
        except Exception as e:
            LOGGER.debug(f"Error while fetching RedHat Security Data CVEs : {e}")
            LOGGER.error("Unable to fetch RedHat Security Data CVEs, skipping RSD.")
            if self.session is not None:
                await self.session.close()
            return (list(), list()), self.source_name

        await self.update_cve_entries()

        return self.format_data(self.all_cve_entries), self.source_name
