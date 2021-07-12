# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Retrieval access and caching of NIST CVE database
"""
import asyncio
import datetime
import glob
import gzip
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3

import aiohttp
from bs4 import BeautifulSoup
from rich.progress import track

from cve_bin_tool.async_utils import FileIO, GzipFile, RateLimiter, run_coroutine
from cve_bin_tool.error_handler import (
    AttemptedToWriteOutsideCachedir,
    CVEDataForCurlVersionNotInCache,
    CVEDataForYearNotInCache,
    ErrorHandler,
    ErrorMode,
    NVDRateLimit,
    SHAMismatch,
)
from cve_bin_tool.log import LOGGER
from cve_bin_tool.version import check_latest_version

logging.basicConfig(level=logging.DEBUG)

# database defaults
DISK_LOCATION_BACKUP = os.path.join(
    os.path.expanduser("~"), ".cache", "cve-bin-tool-backup"
)
DISK_LOCATION_DEFAULT = os.path.join(os.path.expanduser("~"), ".cache", "cve-bin-tool")
DBNAME = "cve.db"
OLD_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "cvedb")


class CVEDB:
    """
    Downloads NVD data in json form and stores it on disk in a cache.
    """

    CACHEDIR = DISK_LOCATION_DEFAULT
    BACKUPCACHEDIR = DISK_LOCATION_BACKUP
    FEED = "https://nvd.nist.gov/vuln/data-feeds"
    LOGGER = LOGGER.getChild("CVEDB")
    NVDCVE_FILENAME_TEMPLATE = "nvdcve-1.1-{}.json.gz"
    CURL_CVE_FILENAME_TEMPLATE = "curlcve-{}.json"
    META_LINK = "https://nvd.nist.gov"
    META_REGEX = re.compile(r"\/feeds\/json\/.*-[0-9]*\.[0-9]*-[0-9]*\.meta")
    RANGE_UNSET = ""

    def __init__(
        self,
        feed=None,
        cachedir=None,
        backup_cachedir=None,
        version_check=True,
        session=None,
        error_mode=ErrorMode.TruncTrace,
    ):
        self.feed = feed if feed is not None else self.FEED
        self.cachedir = cachedir if cachedir is not None else self.CACHEDIR
        self.backup_cachedir = (
            backup_cachedir if backup_cachedir is not None else self.BACKUPCACHEDIR
        )
        self.error_mode = error_mode
        # Will be true if refresh was successful
        self.was_updated = False

        # version update
        self.version_check = version_check

        # set up the db if needed
        self.dbpath = os.path.join(self.cachedir, DBNAME)
        self.connection = None
        self.session = session
        self.cve_count = -1

        if not os.path.exists(self.dbpath):
            self.rollback_cache_backup()

    def get_cve_count(self):
        if self.cve_count == -1:
            # Force update
            self.check_cve_entries()
        return self.cve_count

    def get_db_update_date(self):
        # last time when CVE data was updated
        self.time_of_last_update = datetime.datetime.fromtimestamp(
            os.path.getmtime(self.dbpath)
        )
        return os.path.getmtime(self.dbpath)

    async def getmeta(self, session, meta_url):
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

    async def nist_scrape(self, session):
        async with await session.get(self.feed) as response:
            response.raise_for_status()
            page = await response.text()
            json_meta_links = self.META_REGEX.findall(page)
            return dict(
                await asyncio.gather(
                    *(
                        self.getmeta(session, f"{self.META_LINK}{meta_url}")
                        for meta_url in json_meta_links
                    )
                )
            )

    async def cache_update(self, session, url, sha, chunk_size=16 * 1024):
        """
        Update the cache for a single year of NVD data.
        """
        filename = url.split("/")[-1]
        # Ensure we only write to files within the cachedir
        filepath = os.path.abspath(os.path.join(self.cachedir, filename))
        if not filepath.startswith(os.path.abspath(self.cachedir)):
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise AttemptedToWriteOutsideCachedir(filepath)
        # Validate the contents of the cached file
        if os.path.isfile(filepath):
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
                os.unlink(filepath)
                self.LOGGER.warning(
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
            os.unlink(filepath)
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise SHAMismatch(f"{url} (have: {gotsha}, want: {sha})")

    @staticmethod
    async def get_curl_versions(session):
        regex = re.compile(r"vuln-(\d+.\d+.\d+)\.html")
        async with await session.get(
            "https://curl.haxx.se/docs/vulnerabilities.html"
        ) as response:
            response.raise_for_status()
            html = await response.text()
        matches = regex.finditer(html)
        return [match.group(1) for match in matches]

    async def download_curl_version(self, session, version):
        async with await session.get(
            f"https://curl.haxx.se/docs/vuln-{version}.html"
        ) as response:
            response.raise_for_status()
            html = await response.text()
        soup = BeautifulSoup(html, "html.parser")
        table = soup.find("table")
        if not table:
            return
        headers = table.find_all("th")
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
        filepath = os.path.abspath(
            os.path.join(self.cachedir, f"curlcve-{version}.json")
        )
        async with FileIO(filepath, "w") as f:
            await f.write(json.dumps(json_data, indent=4))

    async def refresh(self):
        """Refresh the cve database and check for new version."""
        # refresh the database
        if not os.path.isdir(self.cachedir):
            os.makedirs(self.cachedir)
        # check for the latest version
        if self.version_check:
            self.LOGGER.info("Checking if there is a newer version.")
            check_latest_version()
        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=19)
            self.session = RateLimiter(
                aiohttp.ClientSession(connector=connector, trust_env=True)
            )
        self.LOGGER.info("Downloading CVE data...")
        nvd_metadata, curl_metadata = await asyncio.gather(
            asyncio.ensure_future(self.nist_scrape(self.session)),
            asyncio.ensure_future(self.get_curl_versions(self.session)),
        )
        tasks = [
            asyncio.ensure_future(self.cache_update(self.session, url, meta["sha256"]))
            for url, meta in nvd_metadata.items()
            if meta is not None
        ]
        # We use gather to create a single task from a set of tasks
        # which download CVEs for each version of curl. Otherwise
        # the progress bar would show that we are closer to
        # completion than we think, because lots of curl CVEs (for
        # each version) have been downloaded
        tasks.append(
            asyncio.gather(
                *(
                    asyncio.ensure_future(
                        self.download_curl_version(self.session, version)
                    )
                    for version in curl_metadata
                )
            )
        )
        total_tasks = len(tasks)

        # error_mode.value will only be greater than 1 if quiet mode.
        if self.error_mode.value > 1:
            iter_tasks = track(
                asyncio.as_completed(tasks),
                description="Downloading CVEs...",
                total=total_tasks,
            )
        else:
            iter_tasks = asyncio.as_completed(tasks)

        for task in iter_tasks:
            await task
        self.was_updated = True
        await self.session.close()
        self.session = None

    def refresh_cache_and_update_db(self):
        self.LOGGER.info("Updating CVE data. This will take a few minutes.")
        # refresh the nvd cache
        run_coroutine(self.refresh())

        # if the database isn't open, open it
        self.init_database()
        self.populate_db()

    def get_cvelist_if_stale(self):
        """Update if the local db is more than one day old.
        This avoids the full slow update with every execution.
        """
        if not os.path.isfile(self.dbpath) or (
            datetime.datetime.today()
            - datetime.datetime.fromtimestamp(os.path.getmtime(self.dbpath))
        ) > datetime.timedelta(hours=24):
            self.refresh_cache_and_update_db()
            self.time_of_last_update = datetime.datetime.today()
        else:
            self.time_of_last_update = datetime.datetime.fromtimestamp(
                os.path.getmtime(self.dbpath)
            )
            self.LOGGER.info(
                "Using cached CVE data (<24h old). Use -u now to update immediately."
            )

    def latest_schema(self, cursor):
        """Check database is using latest schema"""
        self.LOGGER.info("Check database is using latest schema")
        schema_check = "SELECT * FROM cve_severity WHERE 1=0"
        result = cursor.execute(schema_check)
        schema_latest = False
        # Look through column names and check for column added in latest schema
        for col_name in result.description:
            if col_name[0] == "description":
                schema_latest = True
        return schema_latest

    def check_cve_entries(self):
        """Report if database has some CVE entries"""
        self.db_open()
        cursor = self.connection.cursor()
        cve_entries_check = "SELECT COUNT(*) FROM cve_severity"
        cursor.execute(cve_entries_check)
        # Find number of entries
        cve_entries = cursor.fetchone()[0]
        self.LOGGER.info(f"There are {cve_entries} CVE entries in the database")
        self.db_close()
        self.cve_count = cve_entries
        return cve_entries > 0

    def init_database(self):
        """Initialize db tables used for storing cve/version data"""
        self.db_open()
        cursor = self.connection.cursor()
        cve_data_create = """
        CREATE TABLE IF NOT EXISTS cve_severity (
            cve_number TEXT,
            severity TEXT,
            description TEXT,
            score INTEGER,
            cvss_version INTEGER,
            PRIMARY KEY(cve_number)
        )
        """
        version_range_create = """
        CREATE TABLE IF NOT EXISTS cve_range (
            cve_number TEXT,
            vendor TEXT,
            product TEXT,
            version TEXT,
            versionStartIncluding TEXT,
            versionStartExcluding TEXT,
            versionEndIncluding TEXT,
            versionEndExcluding TEXT,
            FOREIGN KEY(cve_number) REFERENCES cve_severity(cve_number)
        )
        """
        index_range = "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)"
        cursor.execute(cve_data_create)
        cursor.execute(version_range_create)
        cursor.execute(index_range)

        # Check that latest schema is being used
        if not self.latest_schema(cursor):
            # Recreate table using latest schema
            self.LOGGER.info("Upgrading database to latest schema")
            cursor.execute("DROP TABLE cve_severity")
            cursor.execute(cve_data_create)
            self.clear_cached_data()
        self.connection.commit()

    def populate_db(self):
        """Function that populates the database from the JSON.

        WARNING: After some inspection of the data, we are assuming that start/end ranges are kept together
        in single nodes.  This isn't *required* by the json so may not be true everywhere.  If that's the case,
        we'll need a better parser to match those together.
        """
        self.db_open()
        cursor = self.connection.cursor()

        insert_severity = """
        INSERT or REPLACE INTO cve_severity(
            CVE_number,
            severity,
            description,
            score,
            cvss_version
        )
        VALUES (?, ?, ?, ?, ?)
        """
        insert_cve_range = """
        INSERT or REPLACE INTO cve_range(
            cve_number,
            vendor,
            product,
            version,
            versionStartIncluding,
            versionStartExcluding,
            versionEndIncluding,
            versionEndExcluding
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        del_cve_range = "DELETE from cve_range where CVE_number=?"

        # error_mode.value will only be greater than 1 if quiet mode.
        if self.error_mode.value > 1:
            years = track(self.nvd_years(), description="Updating CVEs from NVD...")
        else:
            years = self.nvd_years()

        for year in years:
            cve_data = self.load_nvd_year(year)
            self.LOGGER.debug(
                f'Time = {datetime.datetime.today().strftime("%H:%M:%S")}'
            )
            for cve_item in cve_data["CVE_Items"]:
                # the information we want:
                # CVE ID, Severity, Score ->
                # affected {Vendor(s), Product(s), Version(s)}
                cve = {
                    "ID": cve_item["cve"]["CVE_data_meta"]["ID"],
                    "description": cve_item["cve"]["description"]["description_data"][
                        0
                    ]["value"],
                    "severity": "unknown",
                    "score": "unknown",
                    "CVSS_version": "unknown",
                }
                # Get CVSSv3 or CVSSv2 score for output.
                # Details are left as an exercise to the user.
                if "baseMetricV3" in cve_item["impact"]:
                    cve["severity"] = cve_item["impact"]["baseMetricV3"]["cvssV3"][
                        "baseSeverity"
                    ]
                    cve["score"] = cve_item["impact"]["baseMetricV3"]["cvssV3"][
                        "baseScore"
                    ]
                    cve["CVSS_version"] = 3
                elif "baseMetricV2" in cve_item["impact"]:
                    cve["severity"] = cve_item["impact"]["baseMetricV2"]["severity"]
                    cve["score"] = cve_item["impact"]["baseMetricV2"]["cvssV2"][
                        "baseScore"
                    ]
                    cve["CVSS_version"] = 2

                # self.LOGGER.debug(
                #    "Severity: {} ({}) v{}".format(
                #        CVE["severity"], CVE["score"], CVE["CVSS_version"]
                #    )
                # )

                cursor.execute(
                    insert_severity,
                    [
                        cve["ID"],
                        cve["severity"],
                        cve["description"],
                        cve["score"],
                        cve["CVSS_version"],
                    ],
                )

                # Delete any old range entries for this CVE_number
                cursor.execute(del_cve_range, (cve["ID"],))

                # walk the nodes with version data
                # return list of versions
                affects_list = []
                if "configurations" in cve_item:
                    for node in cve_item["configurations"]["nodes"]:
                        # self.LOGGER.debug("NODE: {}".format(node))
                        affects_list.extend(self.parse_node(node))
                        if "children" in node:
                            for child in node["children"]:
                                affects_list.extend(self.parse_node(child))
                # self.LOGGER.debug("Affects: {}".format(affects_list))
                cursor.executemany(
                    insert_cve_range,
                    [
                        (
                            cve["ID"],
                            affected["vendor"],
                            affected["product"],
                            affected["version"],
                            affected["versionStartIncluding"],
                            affected["versionStartExcluding"],
                            affected["versionEndIncluding"],
                            affected["versionEndExcluding"],
                        )
                        for affected in affects_list
                    ],
                )
            self.connection.commit()

        # supplemental data gets added here
        self.supplement_curl()

        self.db_close()

    def parse_node(self, node):
        affects_list = []
        if "cpe_match" in node:
            for cpe_match in node["cpe_match"]:
                # self.LOGGER.debug(cpe_match["cpe23Uri"])
                cpe_split = cpe_match["cpe23Uri"].split(":")
                affects = {
                    "vendor": cpe_split[3],
                    "product": cpe_split[4],
                    "version": cpe_split[5],
                }

                # self.LOGGER.debug(
                #    "Vendor: {} Product: {} Version: {}".format(
                #        affects["vendor"], affects["product"], affects["version"]
                #    )
                # )
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

    def supplement_curl(self):
        """
        Get additional CVE data directly from the curl website amd add it to the cvedb
        """
        self.db_open()
        insert_cve_range = """
        INSERT or REPLACE INTO cve_range(
            cve_number,
            vendor,
            product,
            version,
            versionStartIncluding,
            versionStartExcluding,
            versionEndIncluding,
            versionEndExcluding
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        cursor = self.connection.cursor()
        # No need to track this. It is very fast!
        for version in self.curl_versions():
            cve_list = self.load_curl_version(version)
            # for cve in cve_list:
            cursor.executemany(
                insert_cve_range,
                [
                    (
                        cve["cve"],
                        "haxx",
                        "curl",
                        version,
                        cve["from version"],
                        "",
                        cve["to and including"],
                        "",
                    )
                    for cve in cve_list
                ],
            )
            self.connection.commit()

    def load_nvd_year(self, year):
        """
        Return the dict of CVE data for the given year.
        """
        filename = os.path.join(
            self.cachedir, self.NVDCVE_FILENAME_TEMPLATE.format(year)
        )
        # Check if file exists
        if not os.path.isfile(filename):
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise CVEDataForYearNotInCache(year)
        # Open the file and load the JSON data, log the number of CVEs loaded
        with gzip.open(filename, "rb") as fileobj:
            cves_for_year = json.load(fileobj)
            self.LOGGER.debug(
                f'Year {year} has {len(cves_for_year["CVE_Items"])} CVEs in dataset'
            )
            return cves_for_year

    def nvd_years(self):
        """
        Return the years we have NVD data for.
        """
        return sorted(
            int(filename.split(".")[-3].split("-")[-1])
            for filename in glob.glob(
                os.path.join(self.cachedir, "nvdcve-1.1-*.json.gz")
            )
        )

    def load_curl_version(self, version):
        """
        Return the dict of CVE data for the given curl version.
        """
        filename = os.path.join(
            self.cachedir, self.CURL_CVE_FILENAME_TEMPLATE.format(version)
        )
        # Check if file exists
        if not os.path.isfile(filename):
            with ErrorHandler(mode=self.error_mode, logger=self.LOGGER):
                raise CVEDataForCurlVersionNotInCache(version)
        # Open the file and load the JSON data, log the number of CVEs loaded
        with open(filename, "rb") as fileobj:
            cves_for_version = json.load(fileobj)
            self.LOGGER.debug(
                f"Curl Version {version} has {len(cves_for_version)} CVEs in dataset"
            )
            return cves_for_version

    def curl_versions(self):
        """
        Return the versions we have Curl data for.
        """
        regex = re.compile(r"curlcve-(\d+.\d+.\d).json")
        return [
            regex.search(filename).group(1)
            for filename in glob.glob(os.path.join(self.cachedir, "curlcve-*.json"))
        ]

    def clear_cached_data(self):
        self.create_cache_backup()
        if os.path.exists(self.cachedir):
            self.LOGGER.warning(f"Updating cachedir {self.cachedir}")
            shutil.rmtree(self.cachedir)
        # Remove files associated with pre-1.0 development tree
        if os.path.exists(OLD_CACHE_DIR):
            self.LOGGER.warning(f"Deleting old cachedir {OLD_CACHE_DIR}")
            shutil.rmtree(OLD_CACHE_DIR)

    def db_open(self):
        """Opens connection to sqlite database."""
        if not self.connection:
            self.connection = sqlite3.connect(self.dbpath)

    def db_close(self):
        """Closes connection to sqlite database."""
        if self.connection:
            self.connection.close()
            self.connection = None

    def create_cache_backup(self):
        """Creates a backup of the cachedir in case anything fails"""
        if os.path.exists(self.cachedir):
            self.LOGGER.debug(
                f"Creating backup of cachedir {self.cachedir} at {self.backup_cachedir}"
            )
            self.remove_cache_backup()
            shutil.copytree(self.cachedir, self.backup_cachedir)

    def remove_cache_backup(self):
        """Removes the backup if database was successfully loaded"""
        if os.path.exists(self.backup_cachedir):
            self.LOGGER.debug(f"Removing backup cache from {self.backup_cachedir}")
            shutil.rmtree(self.backup_cachedir)

    def rollback_cache_backup(self):
        """Rollback the cachedir backup in case anything fails"""
        if os.path.exists(os.path.join(self.backup_cachedir, DBNAME)):
            self.LOGGER.info(f"Rolling back the cache to its previous state")
            if os.path.exists(self.cachedir):
                shutil.rmtree(self.cachedir)
            shutil.move(self.backup_cachedir, self.cachedir)

    def __del__(self):
        self.rollback_cache_backup()
