# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
import json
from pathlib import Path

import aiohttp

from cve_bin_tool.async_utils import FileIO, RateLimiter
from cve_bin_tool.data_sources import DISK_LOCATION_DEFAULT, Data_Source
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.log import LOGGER
from cve_bin_tool.version import HTTP_HEADERS


class REDHAT_Source(Data_Source):
    """Data source for fetching CVE data from Red Hat."""

    SOURCE = "REDHAT"
    CACHEDIR = DISK_LOCATION_DEFAULT
    LOGGER = LOGGER.getChild("CVEDB")
    REDHAT_URL = "https://access.redhat.com/hydra/rest/securitydata"
    CVE_ENDPOINT = "/cve.json"

    def __init__(
        self, error_mode: ErrorMode = ErrorMode.TruncTrace, incremental_update=False
    ):
        self.cachedir = self.CACHEDIR
        self.redhat_path = str(Path(self.cachedir) / "redhat")
        self.source_name = self.SOURCE

        self.error_mode = error_mode
        self.incremental_update = incremental_update
        self.time_of_last_update = None

        self.redhat_url = self.REDHAT_URL + self.CVE_ENDPOINT

        self.all_cve_entries = []

        self.session = None

    async def get_req(self, url, session, mode="json"):
        """Gets CVEs using Red Hat Security API."""

        LOGGER.debug(f"RedHat - Get request {url}")
        async with await session.get(url) as r:
            if mode == "bytes":
                content = await r.read()
            else:
                content = await r.json()

        return content

    async def store_data(self, content):
        """Asynchronously stores CVE data in separate JSON files, excluding entries without a CVE ID."""
        for c in content:
            if c["CVE"] != "":
                filepath = Path(self.redhat_path) / (str(c["CVE"]) + ".json")
                r = json.dumps(c)
                async with FileIO(filepath, "w") as f:
                    await f.write(r)
            else:
                LOGGER.info(f"Attempt to write file with no CVE. {content}")

    async def fetch_cves(self):
        """Fetches CVEs from RedHat API and places them in redhat_path."""

        LOGGER.info("Getting RedHat CVEs...")

        from cve_bin_tool import cvedb  # prevent cyclic import

        self.db = cvedb.CVEDB()

        if not Path(self.redhat_path).exists():
            Path(self.redhat_path).mkdir()
            # As no data, force full update
            self.incremental_update = False

        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=10)
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

            # Get all RedHat security updates since the database was last updated
            url = self.redhat_url + "?after=" + str(time_of_last_update.date())
            content = await self.get_req(url, self.session)
            await self.store_data(content)

        else:
            # Get all CVEs from 1999
            year = 1999
            finished = False
            page = 0
            page_size = 1000
            while not finished:
                page = page + 1
                params = f"?after={year}-01-01&page={page}&per_page={page_size}"
                url = self.redhat_url + params
                content = await self.get_req(url, self.session)
                if len(content) > 0:
                    LOGGER.debug(f"Returned {len(content)} items")
                    await self.store_data(content)
                    finished = len(content) != page_size
                else:
                    finished = True

        await self.session.close()
        self.session = None

    async def update_cve_entries(self):
        """Updates CVE entries from CVEs in cache."""

        p = Path(self.redhat_path).glob("**/*")
        # Need to find files which are new to the cache
        last_update_timestamp = (
            self.time_of_last_update.timestamp()
            if self.time_of_last_update is not None
            else 0
        )
        files = [
            x for x in p if x.is_file() and x.stat().st_mtime > last_update_timestamp
        ]
        self.all_cve_entries = []

        if len(files) > 0:
            LOGGER.info(f"Adding {len(files)} RedHat CVE entries")
        for file in files:
            async with FileIO(file, "r", encoding="utf-8") as f:
                r = await f.read()
                try:
                    data = json.loads(r)
                    self.all_cve_entries.append(data)
                except Exception as e:
                    LOGGER.debug(f"{e} - Error processing {file}")

    def format_data(self, all_cve_entries):
        """Extracts essential details and formats information from a list of CVE entries."""
        # Severity mapped to CVSS severities (low, medium, high, critical) based on score
        cvss_severity = {
            0: "LOW",
            1: "LOW",
            2: "LOW",
            3: "LOW",
            4: "MEDIUM",
            5: "MEDIUM",
            6: "MEDIUM",
            7: "HIGH",
            8: "HIGH",
            9: "CRITICAL",
            10: "CRITICAL",
        }

        severity_data = []
        affected_data = []
        LOGGER.debug(f"Processing {len(all_cve_entries)} items")
        item_no = 0
        for cve_item in all_cve_entries:
            try:
                cve_id = cve_item["CVE"]
            except Exception as e:
                LOGGER.debug(
                    f"{e} Unable to process {item_no} {all_cve_entries[item_no]}"
                )
                continue

            item_no = item_no + 1

            score = 0
            severity = None
            if "cvss3_scoring_vector" in cve_item:
                vector = (cve_item["cvss3_scoring_vector"], 3)
                score = cve_item.get("cvss3_score", None)
            elif "cvss_scoring_vector" in cve_item:
                vector = (cve_item["cvss_scoring_vector"], 2)
                score = cve_item.get("cvss_score", None)
            else:
                vector = (None, None)
            if score is not None:
                severity = (
                    cvss_severity[int(float(score))] if int(float(score)) > 0 else None
                )
            # Check we have a CVSS vector to work with
            if vector[0] is not None:
                version = vector[1]
                # Ensure CVSS vector is valid
                if vector[0].endswith("/"):
                    LOGGER.debug(
                        f"{cve_id} : Correcting malformed CVSS vector {vector[0]}"
                    )
                    vector[0] = vector[0][:-1]
            else:
                vector = (None, None)
            description = cve_item.get("bugzilla_description", None)
            if description is None:
                description = "unknown"
            elif description.startswith(cve_id):
                # The description often starts with the name of the CVE. Remove this from the description
                description = description[(len(cve_id)) + 1 :].strip()

            cve = {
                "ID": cve_id,
                "severity": severity if severity is not None else "unknown",
                "description": description,
                "score": score if score is not None else "unknown",
                "CVSS_version": str(version) if vector[0] is not None else "unknown",
                "CVSS_vector": vector[0] if vector[0] is not None else "unknown",
                "last_modified": cve_item["public_date"],
            }
            # Only add CVE if at least one related product found
            cve_to_write = True
            packages = cve_item["affected_packages"]
            for package in packages:
                try:
                    # Package format is <name>:<version>
                    if ":" in package:
                        s = package.split(":")
                        product = s[0]
                        version = s[1]
                        affected = {
                            "cve_id": cve_id,
                            "vendor": "redhat",
                            "product": product,
                            "version": version,
                            "versionStartIncluding": "",
                            "versionStartExcluding": "",
                            "versionEndIncluding": "",
                            "versionEndExcluding": "",
                        }
                        affected_data.append(affected)
                        if cve_to_write:
                            severity_data.append(cve)
                            cve_to_write = False
                    else:
                        # Version not specified
                        LOGGER.debug(f"{cve_id} : Version not specified for {package}")
                except Exception as e:
                    LOGGER.debug(e)
                    LOGGER.debug(f"{cve_id} : Affected {package}")
        return severity_data, affected_data

    async def get_cve_data(self):
        """Fetches Red Hat Security Data CVEs, updates entries, and returns formatted data along with the source name."""
        # skip if connection fails
        try:
            await self.fetch_cves()
        except Exception as e:
            LOGGER.debug(f"Error while fetching RedHat Security Data CVEs : {e}")
            LOGGER.error("Unable to fetch RedHat Security Data CVEs, skipping RedHat.")
            if self.session is not None:
                await self.session.close()
            return (list(), list()), self.source_name

        await self.update_cve_entries()

        return self.format_data(self.all_cve_entries), self.source_name
