# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Handling CVE database
"""
from __future__ import annotations

import asyncio
import datetime
import json
import logging
import shutil
import sqlite3
from os import utime
from pathlib import Path
from typing import Any

import requests
from rich.progress import track

from cve_bin_tool.async_utils import run_coroutine
from cve_bin_tool.data_sources import curl_source, gad_source, nvd_source, osv_source
from cve_bin_tool.error_handler import CVEDBError, ErrorMode
from cve_bin_tool.fetch_json_db import Fetch_JSON_DB
from cve_bin_tool.log import LOGGER
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
        nvd_source.NVD_Source,
        curl_source.Curl_Source,
        osv_source.OSV_Source,
        gad_source.GAD_Source,
    ]

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
        if self.cve_count == -1:
            # Force update
            self.check_cve_entries()
        return self.cve_count

    def check_db_exists(self) -> bool:
        return self.dbpath.is_file()

    def get_db_update_date(self) -> float:
        # last time when CVE data was updated
        if self.check_db_exists():
            self.time_of_last_update = datetime.datetime.fromtimestamp(
                self.dbpath.stat().st_mtime
            )
            return self.dbpath.stat().st_mtime
        # Shouldn't be happenning but just in case....
        self.LOGGER.warning("Database not available. Using default date.")
        self.time_of_last_update = datetime.datetime(2000, 1, 1)
        return self.time_of_last_update.timestamp()

    async def refresh(self) -> None:
        """Refresh the cve database and check for new version."""

        # refresh the database
        if not self.cachedir.is_dir():
            self.cachedir.mkdir(parents=True)

        # check for the latest version
        if self.version_check:
            check_latest_version()

        await self.get_data()

    def refresh_cache_and_update_db(self) -> None:
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
            severity_schema, range_schema, exploit_schema = self.table_schemas()
            if (
                not self.latest_schema("cve_severity", severity_schema)
                or not self.latest_schema("cve_range", range_schema)
                or not self.latest_schema("cve_exploited", exploit_schema)
            ):
                self.refresh_cache_and_update_db()
                self.time_of_last_update = datetime.datetime.today()

    def latest_schema(
        self,
        table_name: str = "",
        table_schema: str = "",
        cursor: sqlite3.Cursor | None = None,
    ) -> bool:
        """Check database is using latest schema"""
        if table_name == "":
            # If no table specified, check cve_range (the last one changed)
            _, range_schema, __ = self.table_schemas()
            return self.latest_schema("cve_range", range_schema)

        self.LOGGER.debug("Check database is using latest schema")
        cursor = self.db_open_and_get_cursor()
        schema_check = f"SELECT * FROM {table_name} WHERE 1=0"
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
        """Report if database has some CVE entries"""
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

    def table_schemas(self):
        """Returns sql commands for creating cve_severity, cve_range and cve_exploited tables."""
        cve_data_create = """
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
            data_source TEXT,
            FOREIGN KEY(cve_number) REFERENCES cve_severity(cve_number)
        )
        """
        exploit_table_create = """
        CREATE TABLE IF NOT EXISTS cve_exploited (
            cve_number TEXT,
            product TEXT,
            description TEXT,
            PRIMARY KEY(cve_number)
        )
        """

        return cve_data_create, version_range_create, exploit_table_create

    def insert_queries(self):
        cve_severity = """
        cve_severity(
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
        """
        insert_severity = f"INSERT or REPLACE INTO {cve_severity}"
        insert_cve_range = """
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
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        insert_exploit = """
        INSERT or REPLACE INTO cve_exploited (
            cve_number,
            product,
            description
        )
        VALUES (?,?,?)
        """
        return insert_severity, insert_cve_range, insert_exploit

    def init_database(self) -> None:
        """Initialize db tables used for storing cve/version data"""

        cursor = self.db_open_and_get_cursor()
        (
            cve_data_create,
            version_range_create,
            exploit_table_create,
        ) = self.table_schemas()
        index_range = "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)"
        cursor.execute(cve_data_create)
        cursor.execute(version_range_create)
        cursor.execute(exploit_table_create)
        cursor.execute(index_range)

        severity_schema, range_schema, exploit_schema = self.table_schemas()
        # Check schema on cve_severity
        if not self.latest_schema("cve_severity", severity_schema, cursor):
            # Recreate table using latest schema
            self.LOGGER.info("Upgrading cve_severity data. This may take some time.")
            self.LOGGER.info(
                "If this step hangs, try using `-u now` to get a fresh db."
            )
            cursor.execute("DROP TABLE cve_severity")
            cursor.execute(cve_data_create)

        # Check schema on cve_range
        if not self.latest_schema("cve_range", range_schema, cursor):
            self.LOGGER.info("Upgrading cve_range data. This may take some time.")
            self.LOGGER.info(
                "If this step hangs, try using `-u now` to get a fresh db."
            )
            cursor.execute("DROP TABLE cve_range")
            cursor.execute(version_range_create)

        # Check schema on cve_exploits
        if not self.latest_schema("cve_exploited", exploit_schema, cursor):
            self.LOGGER.info("Upgrading cve_exploited data. This may take some time.")
            self.LOGGER.info(
                "If this step hangs, try using `-u now` to get a fresh db."
            )
            cursor.execute("DROP TABLE cve_exploited")
            cursor.execute(exploit_table_create)

        if self.connection is not None:
            self.connection.commit()

        self.db_close()

    def populate_db(self) -> None:
        """Function that populates the database from the JSON.

        WARNING: After some inspection of the data, we are assuming that start/end ranges are kept together
        in single nodes.  This isn't *required* by the json so may not be true everywhere.  If that's the case,
        we'll need a better parser to match those together.
        """

        for idx, data in enumerate(self.data):
            _, source_name = data

            if source_name == "NVD":
                self.data.insert(0, self.data.pop(idx))
                break

        for cve_data, source_name in self.data:
            if source_name != "NVD" and cve_data[0] is not None:
                cve_data = self.update_vendors(cve_data)

            severity_data, affected_data = cve_data

            cursor = self.db_open_and_get_cursor()

            if severity_data is not None and len(severity_data) > 0:
                self.populate_severity(severity_data, cursor, data_source=source_name)
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
        (insert_severity, _, _) = self.insert_queries()
        del_cve_range = "DELETE from cve_range where CVE_number=?"

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
        cursor.executemany(del_cve_range, [(cve["ID"],) for cve in severity_data])

    def populate_affected(self, affected_data, cursor, data_source):
        (_, insert_cve_range, _) = self.insert_queries()
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

    def clear_cached_data(self) -> None:
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
        query = """
        SELECT DISTINCT vendor FROM cve_range
        WHERE product=?
        """

        # For python package checkers we don't need the progress bar running
        if type(package_names) != list:
            cursor.execute(query, [package_names])
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
                cursor.execute(query, [package_name["name"].lower()])
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
            self.connection.close()
            self.connection = None

    def create_cache_backup(self) -> None:
        """Creates a backup of the cachedir in case anything fails"""
        if self.cachedir.exists():
            self.LOGGER.debug(
                f"Creating backup of cachedir {self.cachedir} at {self.backup_cachedir}"
            )
            self.remove_cache_backup()
            shutil.copytree(self.cachedir, self.backup_cachedir)

    def copy_db(self, filename, export=True):
        self.db_close()
        if export:
            shutil.copy(self.dbpath, filename)
        else:
            shutil.copy(filename, self.dbpath)

    def remove_cache_backup(self) -> None:
        """Removes the backup if database was successfully loaded"""
        if self.backup_cachedir.exists():
            self.LOGGER.debug(f"Removing backup cache from {self.backup_cachedir}")
            shutil.rmtree(self.backup_cachedir)

    def rollback_cache_backup(self) -> None:
        """Rollback the cachedir backup in case anything fails"""
        if (self.backup_cachedir / DBNAME).exists():
            self.LOGGER.info("Rolling back the cache to its previous state")
            if self.cachedir.exists():
                shutil.rmtree(self.cachedir)
            shutil.move(self.backup_cachedir, self.cachedir)

    def __del__(self) -> None:
        self.rollback_cache_backup()

    # Methods to check and update exploits

    def update_exploits(self):
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        r = requests.get(url, timeout=300)
        data = r.json()
        cves = data["vulnerabilities"]
        exploit_list = []
        for cve in cves:
            exploit_list.append((cve["cveID"], cve["product"], cve["shortDescription"]))
        self.populate_exploit_db(exploit_list)

    def get_cache_exploits(self):
        get_exploits = """
        SELECT cve_number FROM cve_exploited
        """
        cursor = self.db_open_and_get_cursor()
        cursor.row_factory = lambda cursor, row: row[0]
        self.exploits_list = cursor.execute(get_exploits).fetchall()
        self.db_close()
        self.exploit_count = len(self.exploits_list)

    def get_exploits_list(self):
        return self.exploits_list

    def get_exploits_count(self) -> int:
        return self.exploit_count

    def create_exploit_db(self):
        cursor = self.db_open_and_get_cursor()
        (_, _, create_exploit_table) = self.table_schemas()
        cursor = self.db_open_and_get_cursor()
        cursor.execute(create_exploit_table)
        self.connection.commit()
        self.db_close()

    def populate_exploit_db(self, exploits):
        (_, _, insert_exploit) = self.insert_queries()
        cursor = self.db_open_and_get_cursor()
        cursor.executemany(insert_exploit, exploits)
        self.connection.commit()
        self.db_close()

    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def get_all_records_in_table(self, table_name):
        cursor = self.db_open_and_get_cursor()
        cursor.row_factory = self.dict_factory
        cursor.execute(f"SELECT * FROM '{table_name}' ")
        # fetchall as result
        results = cursor.fetchall()
        self.db_close()
        return json.dumps(results)

    def delete_old_files_if_exists(self, path):
        if not ((path / "metadata.json").exists()):
            return
        with open(path / "metadata.json") as file:
            meta_data = file.read()
            meta_data = json.loads(meta_data)
            for meta in meta_data:
                if (path / meta).is_dir():
                    shutil.rmtree(path / meta)
        Path.unlink(path / "metadata.json")

    def db_to_json(self, path):
        path = Path(path)
        if not path.is_dir():
            Path.mkdir(path)
        else:
            self.delete_old_files_if_exists(path)
        cursor = self.db_open_and_get_cursor()
        # select all the tables from the database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
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
                year = result["cve_number"].split("-")
                if len(year) > 0 and len(year[0]) == 4 and year[0].isdigit():
                    year = year[0]
                elif len(year) > 1 and len(year[1]) == 4 and year[1].isdigit():
                    year = year[1]
                elif len(year) > 2 and len(year[2]) == 4 and year[2].isdigit():
                    year = year[2]
                else:
                    year = "other"

                if year not in data:
                    data[year] = []
                data[year].append(result)

            for year in data:
                meta_data["db"][table_name[0]].append(year)
                with open(path / table_name[0] / f"{year}.json", "a+") as file:
                    file.write(json.dumps(data[year]))

        with open(path / "metadata.json", "w+") as file:
            file.write(json.dumps(meta_data))

        self.db_close()

    def json_to_db(self, cursor, db_column, json_data):
        (insert_severity, insert_cve_range, insert_exploit) = self.insert_queries()
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
            cursor.executemany(insert_exploit, values)
        elif db_column == "cve_range":
            cursor.executemany(insert_cve_range, values)
        elif db_column == "cve_severity":
            cursor.executemany(insert_severity, values)

    def json_to_db_wrapper(self, path):
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
            (
                cve_data_create,
                version_range_create,
                exploit_table_create,
            ) = self.table_schemas()
            index_range = "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)"
            cursor.execute(cve_data_create)
            cursor.execute(version_range_create)
            cursor.execute(exploit_table_create)
            cursor.execute(index_range)
            metadata_fd = open(path / "metadata.json")
            metadata = json.loads(metadata_fd.read())
            metadata_fd.close()
            for dir in track(
                metadata["db"], description="Import database from JSON files...."
            ):
                for year in (path / dir).iterdir():
                    json_fd = open(year)
                    data = json.loads(json_fd.read())
                    json_fd.close()
                    self.json_to_db(cursor, dir, data)
                    self.connection.commit()
            self.db_close()
            self.remove_cache_backup()
        except Exception:
            LOGGER.error(
                "Given directory is not valid! Please recheck the directory path"
            )
            return -1

    def fetch_from_mirror(self, mirror):
        if not self.cachedir.exists():
            self.cachedir.mkdir()
        json_db = Fetch_JSON_DB(mirror, self.cachedir, self.error_mode)
        run_coroutine(json_db.handle_download())
        json_data_path = self.cachedir / "json_data"
        if (json_data_path / "metadata.json").exists() and self.json_to_db_wrapper(
            json_data_path
        ) != -1:
            self.time_of_last_update = json_db.metadata["timestamp"]
            utime(self.dbpath, (self.time_of_last_update, self.time_of_last_update))
        else:
            self.clear_cached_data()
            return -1
