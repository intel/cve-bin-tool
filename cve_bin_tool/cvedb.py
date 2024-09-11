# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Handling CVE database
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime
import json
import logging
import shutil
import sqlite3
import tempfile
from datetime import date
from os import utime
from pathlib import Path
from typing import Any

import gnupg
from rich.progress import track

from cve_bin_tool.async_utils import run_coroutine
from cve_bin_tool.data_sources import (
    curl_source,
    epss_source,
    gad_source,
    nvd_source,
    osv_source,
    purl2cpe_source,
)
from cve_bin_tool.error_handler import ERROR_CODES, CVEDBError, ErrorMode, SigningError
from cve_bin_tool.fetch_json_db import Fetch_JSON_DB
from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import make_http_requests
from cve_bin_tool.version import check_latest_version

logging.basicConfig(level=logging.DEBUG)

# database defaults
DISK_LOCATION_DEFAULT = Path("~").expanduser() / ".cache" / "cve-bin-tool"
DISK_LOCATION_BACKUP = Path("~").expanduser() / ".cache" / "cve-bin-tool-backup"
DBNAME = "cve.db"
OLD_CACHE_DIR = Path("~") / ".cache" / "cvedb"


class CVEDB:
    """
    Retrieves CVE data from data sources and handles CVE Database.
    The sources can be found in the cve_bin_tool/data_sources/ directory.
    """

    CACHEDIR = DISK_LOCATION_DEFAULT
    BACKUPCACHEDIR = DISK_LOCATION_BACKUP
    LOGGER = LOGGER.getChild("CVEDB")
    SOURCES = [
        curl_source.Curl_Source,
        epss_source.Epss_Source,
        osv_source.OSV_Source,
        gad_source.GAD_Source,
        purl2cpe_source.PURL2CPE_Source,
        nvd_source.NVD_Source,  # last to avoid data overwrites
    ]

    TABLE_SCHEMAS = {
        "cve_severity": """
        CREATE TABLE IF NOT EXISTS cve_severity (
            cve_number TEXT,
            severity TEXT,
            description TEXT,
            score INTEGER,
            cvss_version INTEGER,
            cvss_vector TEXT,
            data_source TEXT,
            last_modified TIMESTAMP,
            PRIMARY KEY(cve_number, data_source)
        )
        """,
        "cve_range": """
        CREATE TABLE IF NOT EXISTS cve_range (
            cve_number TEXT,
            vendor TEXT,
            product TEXT,
            version TEXT,
            versionStartIncluding TEXT,
            versionStartExcluding TEXT,
            versionEndIncluding TEXT,
            versionEndExcluding TEXT,
            data_source TEXT,
            FOREIGN KEY(cve_number, data_source) REFERENCES cve_severity(cve_number, data_source)
        )
        """,
        "cve_exploited": """
        CREATE TABLE IF NOT EXISTS cve_exploited (
            cve_number TEXT,
            product TEXT,
            description TEXT,
            PRIMARY KEY(cve_number)
        )
        """,
        "cve_metrics": """
        CREATE TABLE IF NOT EXISTS cve_metrics (
            cve_number TEXT,
            metric_id INTEGER,
            metric_score REAL,
            metric_field TEXT,
            FOREIGN KEY(cve_number) REFERENCES cve_severity(cve_number),
            FOREIGN KEY(metric_id) REFERENCES metrics(metrics_id)
        )
        """,
        "metrics": """
        CREATE TABLE IF NOT EXISTS metrics (
            metrics_id  INTEGER,
            metrics_name TEXT,
            PRIMARY KEY(metrics_id)
        )
        """,
        "mismatch": """
        CREATE TABLE IF NOT EXISTS mismatch (
            purl TEXT,
            vendor TEXT,
            PRIMARY KEY (purl, vendor)
        )
        """,
        "purl2cpe": """
        CREATE TABLE IF NOT EXISTS purl2cpe (
            purl TEXT,
            cpe TEXT,
            UNIQUE(purl,cpe)
        )
        """,
    }

    # This is mostly to make bandit happier because we won't be
    # executing compound strings.
    TABLE_DROP = {
        "cve_severity": "DROP TABLE cve_severity",
        "cve_range": "DROP TABLE cve_range",
        "cve_exploited": "DROP TABLE cve_exploited",
        "cve_metrics": "DROP TABLE cve_metrics",
        "metrics": "DROP TABLE metrics",
        "mismatch": "DROP TABLE mismatch",
        "purl2cpe": "DROP TABLE purl2cpe",
    }

    INDEXES = {
        "range": "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)",
        "purl": "CREATE INDEX IF NOT EXISTS purl_index ON mismatch (purl)",
    }

    EMPTY_SELECT_QUERIES = {
        "cve_severity": "SELECT * FROM cve_severity WHERE 1=0",
        "cve_range": "SELECT * FROM cve_range WHERE 1=0",
        "cve_exploited": "SELECT * FROM cve_exploited WHERE 1=0",
        "cve_metrics": "SELECT * FROM cve_metrics WHERE 1=0",
        "metrics": "SELECT * FROM metrics WHERE 1=0",
        "mismatch": "SELECT * FROM mismatch WHERE 1=0",
        "purl2cpe": "SELECT * FROM purl2cpe WHERE 1=0",
    }

    INSERT_QUERIES = {
        "insert_severity": """
       INSERT or REPLACE INTO cve_severity(
            CVE_number,
            severity,
            description,
            score,
            cvss_version,
            cvss_vector,
            data_source,
            last_modified
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        "insert_cve_range": """
        INSERT or REPLACE INTO cve_range(
            cve_number,
            vendor,
            product,
            version,
            versionStartIncluding,
            versionStartExcluding,
            versionEndIncluding,
            versionEndExcluding,
            data_source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        "insert_exploit": """
        INSERT or REPLACE INTO cve_exploited (
            cve_number,
            product,
            description
            )
            VALUES (?,?,?)
        """,
        "insert_cve_metrics": """
        INSERT or REPLACE INTO cve_metrics (
            cve_number,
            metric_id,
            metric_score,
            metric_field
            )
            VALUES (?, ?, ?, ?)
        """,
        "insert_metrics": """
            INSERT or REPLACE INTO metrics (
                metrics_id,
                metrics_name
            )
            VALUES (?, ?)
        """,
    }

    def __init__(
        self,
        sources=None,
        cachedir: str | None = None,
        backup_cachedir: str | None = None,
        version_check: bool = True,
        error_mode: ErrorMode = ErrorMode.TruncTrace,
    ):
        self.sources = (
            sources
            if sources is not None
            else [x(error_mode=error_mode) for x in self.SOURCES]
        )
        self.cachedir = Path(cachedir) if cachedir is not None else self.CACHEDIR
        self.backup_cachedir = (
            Path(backup_cachedir)
            if backup_cachedir is not None
            else self.BACKUPCACHEDIR
        )
        self.error_mode = error_mode

        # Will be true if refresh was successful
        self.was_updated = False

        # version update
        self.version_check = version_check

        # set up the db if needed
        self.dbpath = self.cachedir / DBNAME
        self.connection: sqlite3.Connection | None = None

        self.data: list[Any] = []
        self.cve_count = -1
        self.all_cve_entries: list[dict[str, Any]] | None = None

        self.exploits_list: list[Any] = []
        self.exploit_count = 0

        if not self.dbpath.exists():
            self.rollback_cache_backup()

    def get_cve_count(self) -> int:
        """Update the number of CVE entries if necessary and return the number of CVEs."""
        if self.cve_count == -1:
            # Force update
            self.check_cve_entries()
        return self.cve_count

    def check_db_exists(self) -> bool:
        """Return whether the database file exists or not."""
        return self.dbpath.is_file()

    def get_db_update_date(self) -> float:
        """Determine the time the CVE database was last modified."""
        # last time when CVE data was updated
        if self.check_db_exists():
            self.time_of_last_update = datetime.datetime.fromtimestamp(
                self.dbpath.stat().st_mtime
            )
            return self.dbpath.stat().st_mtime
        # Shouldn't be happening but just in case....
        self.LOGGER.warning("Database not available. Using default date.")
        self.time_of_last_update = datetime.datetime(2000, 1, 1)
        return self.time_of_last_update.timestamp()

    async def refresh(self) -> None:
        """Refresh the CVE database and check for new version."""

        # refresh the database
        if not self.cachedir.is_dir():
            self.cachedir.mkdir(parents=True)

        # check for the latest version
        if self.version_check:
            check_latest_version()

        await self.get_data()

    def refresh_cache_and_update_db(self) -> None:
        """Refresh cached NVD and update CVE database with latest data."""
        self.LOGGER.debug("Updating CVE data. This will take a few minutes.")
        # refresh the nvd cache
        run_coroutine(self.refresh())

        # if the database isn't open, open it
        self.init_database()
        self.populate_db()
        self.LOGGER.debug("Updating exploits data.")
        self.create_exploit_db()
        self.update_exploits()

    def get_cvelist_if_stale(self) -> None:
        """Update if the local db is more than one day old.
        This avoids the full slow update with every execution.
        """
        if not self.dbpath.is_file() or (
            datetime.datetime.today()
            - datetime.datetime.fromtimestamp(self.dbpath.stat().st_mtime)
        ) > datetime.timedelta(hours=24):
            self.refresh_cache_and_update_db()
            self.time_of_last_update = datetime.datetime.today()
        else:
            _ = self.get_db_update_date()
            self.LOGGER.info(
                "Using cached CVE data (<24h old). Use -u now to update immediately."
            )
            if (
                not self.latest_schema(
                    "cve_severity", self.TABLE_SCHEMAS["cve_severity"]
                )
                or not self.latest_schema("cve_range", self.TABLE_SCHEMAS["cve_range"])
                or not self.latest_schema(
                    "cve_exploited", self.TABLE_SCHEMAS["cve_exploited"]
                )
            ):
                self.refresh_cache_and_update_db()
                self.time_of_last_update = datetime.datetime.today()

    def latest_schema(
        self,
        table_name: str = "",
        table_schema="",
        cursor: sqlite3.Cursor | None = None,
    ) -> bool:
        """Check database is using latest schema"""
        if table_name == "":
            # If no table specified, check cve_range (the last one changed)
            range_schema = self.TABLE_SCHEMAS["cve_range"]
            return self.latest_schema("cve_range", range_schema)

        self.LOGGER.debug("Check database is using latest schema")
        cursor = self.db_open_and_get_cursor()
        schema_check = self.EMPTY_SELECT_QUERIES[table_name]
        result = cursor.execute(schema_check)
        schema_latest = False

        if not cursor:
            self.db_close()

        # getting schema from command
        lines = table_schema.split("(")[1].split(",")

        table_schema = [x.split("\n")[1].strip().split(" ")[0] for x in lines]
        table_schema.pop()

        # getting current schema from cve_severity
        current_schema = [x[0] for x in result.description]

        if table_schema == current_schema:
            schema_latest = True

        # check for cve_

        return schema_latest

    def check_cve_entries(self) -> bool:
        """Report if database has some CVE entries."""
        cursor = self.db_open_and_get_cursor()
        cve_entries_check = "SELECT data_source, COUNT(*) as number FROM cve_severity GROUP BY data_source ORDER BY number DESC"
        cursor.execute(cve_entries_check)
        # Find number of entries
        cve_entries = 0
        data_entries = {}
        rows = cursor.fetchall()
        for row in rows:
            source = row[0]
            entries = row[1]
            cve_entries = cve_entries + entries
            data_entries[source] = entries
        self.LOGGER.info(f"There are {cve_entries} CVE entries in the database")
        for data_entry in data_entries:
            self.LOGGER.info(
                f"There are {data_entries[data_entry]} CVE entries from {data_entry} in the database"
            )
        self.db_close()
        self.cve_count = cve_entries
        return cve_entries > 0

    async def get_data(self):
        """Get CVE data from datasources"""
        tasks = []

        for source in self.sources:
            if source is not None:
                tasks.append(source.get_cve_data())

        for r in await asyncio.gather(*tasks):
            self.data.append(r)

    def init_database(self) -> None:
        """Initialize db tables used for storing cve/version data."""

        cursor = self.db_open_and_get_cursor()

        # Create all tables from latest schemas
        for table in self.TABLE_SCHEMAS:
            cursor.execute(self.TABLE_SCHEMAS[table])

        # add indexes
        for index in self.INDEXES:
            cursor.execute(self.INDEXES[index])

        # Check schemas
        for table in self.TABLE_SCHEMAS:
            if not self.latest_schema(table, self.TABLE_SCHEMAS[table], cursor):
                self.LOGGER.info(f"Upgrading {table} data. This may take some time.")
                self.LOGGER.info(
                    "If this step hangs, try using `-u now` to get a fresh db."
                )
                cursor.execute(self.TABLE_DROP[table])
                cursor.execute(self.TABLE_SCHEMAS[table])

        if self.connection is not None:
            self.connection.commit()

        self.db_close()

    def populate_purl2cpe(self):
        """Transfers data from PURL2CPE database to CVE database."""

        purl2cpe_conn = sqlite3.connect(self.cachedir / "purl2cpe/purl2cpe.db")
        purl2cpe_cursor = purl2cpe_conn.cursor()

        cve_conn = sqlite3.connect(self.dbpath)
        cve_cursor = cve_conn.cursor()

        # we are occasionally seeing an error where the cache doesn't have
        # purl2cpe and thus we get an error, so attempt to initalize here
        cve_cursor.execute(self.TABLE_SCHEMAS["purl2cpe"])
        cve_cursor.execute(self.INDEXES["purl"])

        purl2cpe_cursor.execute("SELECT purl, cpe FROM purl2cpe")

        insert_query = """
            INSERT INTO purl2cpe (purl, cpe)
            VALUES (?, ?)
            ON CONFLICT DO NOTHING;
        """
        rows = purl2cpe_cursor.fetchall()
        cve_cursor.executemany(insert_query, rows)

        cve_conn.commit()
        purl2cpe_conn.close()
        cve_conn.close()

    def populate_db(self) -> None:
        """Function that populates the database from the JSON.

        WARNING: After some inspection of the data, we are assuming that start/end ranges are kept together
        in single nodes.  This isn't *required* by the json so may not be true everywhere.  If that's the case,
        we'll need a better parser to match those together.
        """

        self.populate_metrics()
        # EPSS uses metrics table to get the EPSS metric id.
        # It can't be run before creation of metrics table.

        for idx, data in enumerate(self.data):
            _, source_name = data

            if source_name == "NVD":
                self.data.insert(0, self.data.pop(idx))
                break

        for cve_data, source_name in self.data:
            # if source_name != "NVD" and cve_data[0] is not None:
            #    cve_data = self.update_vendors(cve_data)

            if source_name == "PURL2CPE":
                self.populate_purl2cpe()

            if source_name == "EPSS":
                if cve_data is not None:
                    self.store_epss_data(cve_data)

            else:
                severity_data, affected_data = cve_data

                cursor = self.db_open_and_get_cursor()

                if severity_data is not None and len(severity_data) > 0:
                    self.populate_severity(
                        severity_data, cursor, data_source=source_name
                    )
                    self.populate_cve_metrics(severity_data, cursor)
                if affected_data is not None:
                    self.populate_affected(
                        affected_data,
                        cursor,
                        data_source=source_name,
                    )
                if self.connection is not None:
                    self.connection.commit()
                self.db_close()

    def populate_severity(self, severity_data, cursor, data_source):
        """Populate the database with CVE severities."""
        insert_severity = self.INSERT_QUERIES["insert_severity"]
        del_cve_range = "DELETE from cve_range where CVE_number=? and data_source=?"

        for cve in severity_data:
            # Check no None values
            if not bool(cve.get("severity")):
                LOGGER.debug(f"Update severity for {cve['ID']} {data_source}")
                cve["severity"] = "unknown"
            if not bool(cve.get("description")):
                LOGGER.debug(f"Update description for {cve['ID']} {data_source}")
                cve["description"] = "unknown"
            if not bool(cve.get("score")):
                LOGGER.debug(f"Update score for {cve['ID']} {data_source}")
                cve["score"] = "unknown"
            if not bool(cve.get("CVSS_version")):
                LOGGER.debug(f"Update CVSS version for {cve['ID']} {data_source}")
                cve["CVSS_version"] = "unknown"
            if not bool(cve.get("CVSS_vector")):
                LOGGER.debug(f"Update CVSS Vector for {cve['ID']} {data_source}")
                cve["CVSS_vector"] = "unknown"

        for cve in severity_data:
            try:
                cursor.execute(
                    insert_severity,
                    [
                        cve["ID"],
                        cve["severity"].upper(),
                        cve["description"],
                        cve["score"],
                        cve["CVSS_version"],
                        cve["CVSS_vector"],
                        data_source,
                        cve["last_modified"],
                    ],
                )
            except Exception as e:
                LOGGER.info(f"Unable to insert data for {data_source} - {e}\n{cve}")

        # Delete any old range entries for this CVE_number
        for cve in severity_data:
            cursor.execute(del_cve_range, [cve["ID"], data_source])

    def populate_cve_metrics(self, severity_data, cursor):
        """Adds data into CVE metrics table."""
        insert_cve_metrics = self.INSERT_QUERIES["insert_cve_metrics"]

        for cve in severity_data:
            # Check no None values
            if not bool(cve.get("score")):
                LOGGER.debug(f"Update score for {cve['ID']}")
                cve["score"] = "unknown"
            if not bool(cve.get("CVSS_version")):
                LOGGER.debug(f"Update CVSS version for {cve['ID']}")
                cve["CVSS_version"] = "unknown"
            if not bool(cve.get("CVSS_vector")):
                LOGGER.debug(f"Update CVSS Vector for {cve['ID']}")
                cve["CVSS_vector"] = "unknown"

        for cve in severity_data:
            try:
                metric = self.metric_finder(cursor, cve)
                cursor.execute(
                    insert_cve_metrics,
                    [
                        cve["ID"],
                        metric,
                        cve["score"],
                        cve["CVSS_vector"],
                    ],
                )
            except Exception as e:
                LOGGER.info(f"Unable to insert data for {e}\n{cve}")

    def populate_affected(self, affected_data, cursor, data_source):
        """Populate database with affected versions."""
        insert_cve_range = self.INSERT_QUERIES["insert_cve_range"]
        try:
            cursor.executemany(
                insert_cve_range,
                [
                    (
                        affected["cve_id"],
                        affected["vendor"],
                        affected["product"],
                        affected["version"],
                        affected["versionStartIncluding"],
                        affected["versionStartExcluding"],
                        affected["versionEndIncluding"],
                        affected["versionEndExcluding"],
                        data_source,
                    )
                    for affected in affected_data
                ],
            )
        except Exception as e:
            LOGGER.info(f"Unable to insert data for {data_source} - {e}")

    def populate_metrics(self):
        """Adding data to metric table."""
        cursor = self.db_open_and_get_cursor()
        # Insert a row without specifying cve_metrics_id
        insert_metrics = self.INSERT_QUERIES["insert_metrics"]
        data = [
            (1, "EPSS"),
            (2, "CVSS-2"),
            (3, "CVSS-3"),
        ]
        # Execute the insert query for each row
        for row in data:
            cursor.execute(insert_metrics, row)
        self.connection.commit()
        self.db_close()

    def metric_finder(self, cursor, cve):
        """
        SQL query to retrieve the metrics_name based on the metrics_id
        currently cve["CVSS_version"] return 2,3 based on there version and they are mapped accordingly to there metrics name in metrics table.
        """
        query = """
        SELECT metrics_id FROM metrics
        WHERE metrics_id=?
        """
        metric = None
        if cve["CVSS_version"] == "unknown":
            metric = "unknown"
        else:
            cursor.execute(query, [cve.get("CVSS_version")])
            # Fetch all the results of the query and use 'map' to extract only the 'metrics_name' from the result
            metric = list(map(lambda x: x[0], cursor.fetchall()))
            # Since the query is expected to return a single result, extract the first item from the list and store it in 'metric'
            metric = metric[0]
        return metric

    def clear_cached_data(self) -> None:
        """Delete cachedir and old cachedir."""
        self.create_cache_backup()
        if self.cachedir.exists():
            self.LOGGER.warning(f"Updating cachedir {self.cachedir}")
            shutil.rmtree(self.cachedir)
        # Remove files associated with pre-1.0 development tree
        if OLD_CACHE_DIR.exists():
            self.LOGGER.warning(f"Deleting old cachedir {OLD_CACHE_DIR}")
            shutil.rmtree(OLD_CACHE_DIR)

    def get_vendor_product_pairs(self, package_names) -> list[dict[str, str]]:
        """
        Fetches vendor from the database for packages that doesn't have vendor info for Package List Parser Utility and Universal Python package checker.
        """
        cursor = self.db_open_and_get_cursor()
        vendor_package_pairs = []
        query = (
            "SELECT DISTINCT vendor FROM cve_range WHERE product=? AND data_source IN (%s)"  # nosec
            % ",".join("?" for i in self.sources)
        )

        data_sources = list(map(lambda x: x.source_name, self.sources))
        # For python package checkers we don't need the progress bar running
        if type(package_names) is not list:
            cursor.execute(query, [package_names] + data_sources)
            vendors = list(map(lambda x: x[0], cursor.fetchall()))

            for vendor in vendors:
                if vendor != "":
                    vendor_package_pairs.append(
                        {
                            "vendor": vendor,
                            "product": package_names,
                        }
                    )
            if len(vendor_package_pairs) > 1:
                self.LOGGER.debug(f"Multiple vendors found for {package_names}")
                for entry in vendor_package_pairs:
                    self.LOGGER.debug(f'{entry["product"]} - {entry["vendor"]}')
        else:
            for package_name in track(
                package_names, description="Processing the given list...."
            ):
                cursor.execute(query, [package_name["name"].lower()] + data_sources)
                vendors = list(map(lambda x: x[0], cursor.fetchall()))
                for vendor in vendors:
                    if vendor != "":
                        vendor_package_pairs.append(
                            {
                                "vendor": vendor,
                                "product": package_name["name"],
                            }
                        )
        self.db_close()

        return vendor_package_pairs

    def update_vendors(self, cve_data):
        """Get vendors for products and update CVE data."""
        updated_severity = []
        updated_affected = []

        severity_data, affected_data = cve_data
        cursor = self.db_open_and_get_cursor()
        create_index = "CREATE INDEX IF NOT EXISTS product_vendor_index ON cve_range (product, vendor)"
        drop_index = "DROP INDEX product_vendor_index"

        query = """
        SELECT DISTINCT vendor FROM cve_range
        WHERE product=?
        """

        cursor.execute(create_index)

        sel_cve = set()

        for affected in affected_data:
            cursor.execute(query, [affected["product"]])
            vendors = list(map(lambda x: x[0], cursor.fetchall()))

            if len(vendors) == 1:
                affected["vendor"] = vendors[0]
            else:
                for vendor in vendors:
                    if vendor == affected["vendor"]:
                        updated_affected.append(affected)
                        sel_cve.add(affected["cve_id"])
                continue

            updated_affected.append(affected)
            sel_cve.add(affected["cve_id"])

        for cve in severity_data:
            if cve["ID"] in sel_cve:
                updated_severity.append(cve)

        cursor.execute(drop_index)

        self.db_close()

        return updated_severity, updated_affected

    def db_open_and_get_cursor(self) -> sqlite3.Cursor:
        """Opens connection to sqlite database, returns cursor object."""

        if not self.connection:
            self.connection = sqlite3.connect(self.dbpath)
        if self.connection is not None:
            cursor = self.connection.cursor()
        if cursor is None:
            # if this happens somsething has gone horribly wrong
            LOGGER.error("Database cursor does not exist")
            raise CVEDBError
        return cursor

    def db_close(self) -> None:
        """Closes connection to sqlite database."""
        if self.connection:
            self.connection.commit()
            self.connection.close()
            self.connection = None

    def create_cache_backup(self) -> None:
        """Creates a backup of the cachedir in case anything fails."""
        if self.cachedir.exists():
            self.LOGGER.debug(
                f"Creating backup of cachedir {self.cachedir} at {self.backup_cachedir}"
            )
            self.remove_cache_backup()
            shutil.copytree(self.cachedir, self.backup_cachedir)

    def copy_db(self, filename, export=True):
        """Copy database file to or from new path."""
        self.db_close()
        if export:
            shutil.copy(self.dbpath, filename)
        else:
            shutil.copy(filename, self.dbpath)

    def remove_cache_backup(self) -> None:
        """Removes the backup if database was successfully loaded."""
        if self.backup_cachedir.exists():
            self.LOGGER.debug(f"Removing backup cache from {self.backup_cachedir}")
            shutil.rmtree(self.backup_cachedir)

    def rollback_cache_backup(self) -> None:
        """Rollback the cachedir backup in case anything fails."""
        if (self.backup_cachedir / DBNAME).exists():
            self.LOGGER.info("Rolling back the cache to its previous state")
            if self.cachedir.exists():
                shutil.rmtree(self.cachedir)
            shutil.move(self.backup_cachedir, self.cachedir)

    def __del__(self) -> None:
        """Rollback the cachedir backup in case anything fails."""
        self.rollback_cache_backup()

    # Methods to check and update exploits

    def update_exploits(self):
        """Get latest list of vulnerabilities from cisa.gov and add them to the exploits database table."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        data = make_http_requests("json", url=url, timeout=300)
        cves = data["vulnerabilities"]
        exploit_list = []
        for cve in cves:
            exploit_list.append((cve["cveID"], cve["product"], cve["shortDescription"]))
        self.populate_exploit_db(exploit_list)

    def get_cache_exploits(self):
        """Get exploits from database file."""
        get_exploits = """
        SELECT cve_number FROM cve_exploited
        """
        cursor = self.db_open_and_get_cursor()
        cursor.row_factory = lambda cursor, row: row[0]
        self.exploits_list = cursor.execute(get_exploits).fetchall()
        self.db_close()
        self.exploit_count = len(self.exploits_list)

    def get_exploits_list(self):
        """Return list of exploits."""
        return self.exploits_list

    def get_exploits_count(self) -> int:
        """Return number of exploits."""
        return self.exploit_count

    def create_exploit_db(self):
        """Create table of exploits in database if it does not already exist."""
        cursor = self.db_open_and_get_cursor()
        create_exploit_table = self.TABLE_SCHEMAS["cve_exploited"]
        cursor = self.db_open_and_get_cursor()
        cursor.execute(create_exploit_table)
        self.connection.commit()
        self.db_close()

    def populate_exploit_db(self, exploits):
        """Add exploits to the exploits database table."""
        insert_exploit = self.INSERT_QUERIES["insert_exploit"]
        cursor = self.db_open_and_get_cursor()
        cursor.executemany(insert_exploit, exploits)
        self.connection.commit()
        self.db_close()

    def store_epss_data(self, epss_data):
        """Insert Exploit Prediction Scoring System (EPSS) data into database."""
        insert_cve_metrics = self.INSERT_QUERIES["insert_cve_metrics"]
        cursor = self.db_open_and_get_cursor()
        cursor.executemany(insert_cve_metrics, epss_data)
        self.connection.commit()
        self.db_close()

    def dict_factory(self, cursor, row):
        """Helper function for get_all_records_in_table function."""
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def get_all_records_in_table(self, table_name):
        """Return JSON of all records in a database table."""
        cursor = self.db_open_and_get_cursor()
        cursor.row_factory = self.dict_factory
        cursor.execute(f"SELECT * FROM '{table_name}' ")  # nosec
        # fetchall as result
        results = cursor.fetchall()
        self.db_close()
        return json.dumps(results)

    def delete_old_files_if_exists(self, path):
        """Delete old CVE directories and metadata files."""
        DIRECTORIES = [
            "cve_exploited",
            "cve_range",
            "cve_severity",
            "cve_metrics",
            "metrics",
        ]
        for directory in DIRECTORIES:
            if (path / directory).exists():
                shutil.rmtree(path / directory)
        if (path / "metadata.asc").exists():
            Path.unlink(path / "metadata.asc")
        if (path / "metadata.json").exists():
            Path.unlink(path / "metadata.json")

    def db_to_json(self, path, private_key, passphrase):
        """Create JSON of all records in all database tables."""
        if private_key and not passphrase:
            LOGGER.critical(
                "You must provide the passphrase of the private key with --passphrase flag in order to use --pgp-sign flag"
            )
            return ERROR_CODES[SigningError]
        path = Path(path)
        if not path.is_dir():
            Path.mkdir(path)
        else:
            self.delete_old_files_if_exists(path)
        cursor = self.db_open_and_get_cursor()
        # select all the tables from the database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        if private_key:
            temp_gnupg_home = Path(
                tempfile.mkdtemp(prefix=".gnupg-", dir=Path.home())
            )  # storing pgp keyring in home dir instead of /tmp dir due to security reasons
            gpg = gnupg.GPG(gnupghome=temp_gnupg_home)
            key_import_status = gpg.import_keys_file(private_key)
            if key_import_status.results[0]["fingerprint"] is None:
                LOGGER.critical(
                    "Something went wrong while importing the private key. Please try again!"
                )
                shutil.rmtree(temp_gnupg_home)
                return ERROR_CODES[SigningError]

        # for each of the tables, select all the records from the table
        meta_data = {}
        # add timestamp of the last update to the metadata
        meta_data["timestamp"] = self.dbpath.stat().st_mtime
        meta_data["db"] = {}

        for table_name in track(
            tables, description="Export database as JSON files...."
        ):
            # Get the records in table
            meta_data["db"][table_name[0]] = []
            Path.mkdir(path / table_name[0])
            results = json.loads(self.get_all_records_in_table(table_name[0]))
            data = {}

            for result in results:
                year = "other"
                current_year = date.today().year
                if "cve_number" in result:
                    year_breakdown = result["cve_number"].split("-")
                    if (
                        len(year_breakdown) > 0
                        and len(year_breakdown[0]) == 4
                        and year_breakdown[0].isdigit()
                        and int(year_breakdown[0]) >= 2002
                        and int(year_breakdown[0]) <= current_year
                    ):  # CASE 1 EXAMPLE: 2014-04-29 (used in cve_severity and cve_range table for GAD source)
                        year = year_breakdown[0]
                    elif (
                        len(year_breakdown) > 1
                        and len(year_breakdown[1]) == 4
                        and year_breakdown[1].isdigit()
                        and int(year_breakdown[1]) >= 2002
                        and int(year_breakdown[1]) <= current_year
                    ):  # CASE 2 EXAMPLE: CVE-2002-0367
                        year = year_breakdown[1]
                    elif (
                        len(year_breakdown) > 2
                        and len(year_breakdown[2]) == 4
                        and year_breakdown[2].isdigit()
                        and int(year_breakdown[2]) >= 2002
                        and int(year_breakdown[2]) <= current_year
                    ):  # CASE 3 EXAMPLES: neos-sa-2015-001, SA-CORE-2018-003
                        year = year_breakdown[2]

                if year not in data:
                    data[year] = []
                data[year].append(result)

            for year in data:
                meta_data["db"][table_name[0]].append(year)
                json_data = json.dumps(data[year])
                if private_key:
                    json_data_sig = gpg.sign(
                        json_data,
                        passphrase=passphrase,
                        output=(path / table_name[0] / f"{year}.asc"),
                        clearsign=False,
                        detach=True,
                    )
                    if bool(json_data_sig.returncode):
                        LOGGER.critical(
                            "Invalid passphrase! Please recheck the passphrase and try again!"
                        )
                        if temp_gnupg_home.exists():
                            shutil.rmtree(temp_gnupg_home)
                        return ERROR_CODES[SigningError]
                with open(path / table_name[0] / f"{year}.json", "a+") as file:
                    file.write(json_data)

        with open(path / "metadata.json", "w+") as file:
            json_data = json.dumps(meta_data)
            if private_key:
                json_data_sig = gpg.sign(
                    json_data,
                    passphrase=passphrase,
                    output=(path / "metadata.asc"),
                    clearsign=False,
                    detach=True,
                )
                if bool(json_data_sig.returncode):
                    LOGGER.critical(
                        "Invalid passphrase! Please recheck the passphrase and try again!"
                    )
                    if temp_gnupg_home.exists():
                        shutil.rmtree(temp_gnupg_home)
                    return ERROR_CODES[SigningError]
            file.write(json_data)

        self.db_close()

        if private_key and temp_gnupg_home.exists():
            shutil.rmtree(temp_gnupg_home)

    def json_to_db(self, cursor, db_column, json_data):
        """Insert records into database from JSON."""
        columns = []
        for data in json_data:
            column = list(data.keys())
            for col in column:
                if col not in columns:
                    columns.append(col)

        values = []
        for data in json_data:
            value = []
            for i in columns:
                value.append(str(dict(data).get(i)))
            values.append(list(value))

        if db_column == "cve_exploited":
            cursor.executemany(self.INSERT_QUERIES["insert_exploit"], values)
        elif db_column == "cve_range":
            cursor.executemany(self.INSERT_QUERIES["insert_cve_range"], values)
        elif db_column == "cve_severity":
            cursor.executemany(self.INSERT_QUERIES["insert_severity"], values)
        elif db_column == "cve_metrics":
            cursor.executemany(self.INSERT_QUERIES["insert_cve_metrics"], values)
        elif db_column == "metrics":
            cursor.executemany(self.INSERT_QUERIES["insert_metrics"], values)

    def json_to_db_wrapper(self, path, pubkey, ignore_signature, log_signature_error):
        """Initialize the process wrapper to insert records into database from JSON."""
        try:
            path = Path(path)
            if not (path / "metadata.json").is_file():
                LOGGER.error(
                    "Given directory is not valid! Please recheck the directory path"
                )
                return -1

            self.clear_cached_data()

            if path.absolute() == (self.cachedir / "json_data").absolute():
                path = self.backup_cachedir / "json_data"

            if not self.cachedir.is_dir():
                self.cachedir.mkdir(parents=True)

            cursor = self.db_open_and_get_cursor()
            cursor.execute(self.TABLE_SCHEMAS["cve_severity"])
            cursor.execute(self.TABLE_SCHEMAS["cve_range"])
            cursor.execute(self.TABLE_SCHEMAS["cve_exploited"])
            cursor.execute(self.TABLE_SCHEMAS["cve_metrics"])
            cursor.execute(self.TABLE_SCHEMAS["metrics"])
            index_range = "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)"
            cursor.execute(index_range)
            metadata_fd = open(path / "metadata.json")
            metadata = json.loads(metadata_fd.read())
            metadata_fd.close()
            is_signed = Path(path / "metadata.asc").exists()
            if not is_signed:
                LOGGER.warning(
                    "Importing JSON data that is not signed, the JSON data might have been tampered with"
                )
            elif not pubkey and not ignore_signature:
                LOGGER.critical(
                    "The JSON data is signed, so you must provide the public key with --verify flag or use --ignore-sig flag to skip signature verification"
                )
                if not log_signature_error:
                    return ERROR_CODES[SigningError]

            if is_signed and not ignore_signature:
                temp_gnupg_home = Path(tempfile.mkdtemp(prefix=".gnupg-"))
                gpg = gnupg.GPG(gnupghome=temp_gnupg_home)
                key_import_status = gpg.import_keys_file(pubkey)
                if key_import_status.results[0]["fingerprint"] is None:
                    LOGGER.critical(
                        "Something went wrong while importing the public key. Please try again!"
                    )
                    if not log_signature_error:
                        if temp_gnupg_home.exists():
                            shutil.rmtree(temp_gnupg_home)
                        return ERROR_CODES[SigningError]

                with open(path / "metadata.json", "rb") as fd:
                    is_verified = gpg.verify_data(path / "metadata.asc", fd.read())
                if not is_verified:
                    LOGGER.critical("Invalid signature detected!")
                    if not log_signature_error:
                        if temp_gnupg_home.exists():
                            shutil.rmtree(temp_gnupg_home)
                        return ERROR_CODES[SigningError]

            for dir in track(
                metadata["db"], description="Import database from JSON files...."
            ):
                for year in (path / dir).iterdir():
                    if not str(year).endswith(".json"):
                        continue
                    json_fd = open(year)
                    data = json_fd.read()
                    json_fd.close()
                    if is_signed and not ignore_signature:
                        signature_path = str(str(year).replace(".json", ".asc"))
                        is_verified = gpg.verify_data(
                            signature_path, data.encode("utf-8")
                        )
                        if not is_verified:
                            LOGGER.critical("Invalid signature detected!")
                            if not log_signature_error:
                                if temp_gnupg_home.exists():
                                    shutil.rmtree(temp_gnupg_home)
                                return ERROR_CODES[SigningError]
                    self.json_to_db(cursor, dir, json.loads(data))
                    self.connection.commit()

            if is_signed and not ignore_signature and temp_gnupg_home.exists():
                shutil.rmtree(temp_gnupg_home)

            self.db_close()
            self.remove_cache_backup()
        except Exception:
            LOGGER.error(
                "Given directory is not valid! Please recheck the directory path"
            )
            return -1

    def fetch_from_mirror(self, mirror, pubkey, ignore_signature, log_signature_error):
        """Get JSON information from download mirror."""
        if not self.cachedir.exists():
            self.cachedir.mkdir()
        json_db = Fetch_JSON_DB(
            mirror=mirror,
            pubkey=pubkey,
            ignore_signature=ignore_signature,
            cache_dir=self.cachedir,
            log_signature_error=log_signature_error,
            error_mode=self.error_mode,
        )
        run_coroutine(json_db.handle_download())
        json_data_path = self.cachedir / "json_data"
        if (json_data_path / "metadata.json").exists() and self.json_to_db_wrapper(
            path=json_data_path,
            pubkey=pubkey,
            ignore_signature=ignore_signature,
            log_signature_error=log_signature_error,
        ) != -1:
            self.time_of_last_update = json_db.metadata["timestamp"]
            utime(self.dbpath, (self.time_of_last_update, self.time_of_last_update))
        else:
            self.clear_cached_data()
            return -1

    @contextlib.contextmanager
    def with_cursor(self):
        cursor = self.db_open_and_get_cursor()
        try:
            yield cursor
        finally:
            self.db_close()
