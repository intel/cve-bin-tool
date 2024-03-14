# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import sqlite3
import time
from datetime import datetime
from pathlib import Path

from cve_bin_tool.cvedb import DISK_LOCATION_DEFAULT


class InvalidVersionSignatureTable(ValueError):
    """Raised when an invalid table name is given to version_signature"""


class VersionSignatureDb:
    """Methods for version signature data stored in sqlite"""

    def __init__(self, table_name, mapping_function, duration) -> None:
        """Set location on disk data cache will reside.
        Also sets the table name and refresh duration
        """
        if not table_name.isalnum():
            # Basic validation here so we can safely ignore Bandit SQL warnings
            raise InvalidVersionSignatureTable(repr(table_name))
        self.table_name = table_name
        self.update_table_name = f"latest_update_{table_name}"
        self.mapping_function = mapping_function
        self.disk_location = DISK_LOCATION_DEFAULT
        self.duration = duration
        self.conn: sqlite3.Connection | None = None
        self.cursor: sqlite3.Cursor | None = None

    @property
    def dbname(self) -> str:
        """SQLite datebase file where the data is stored."""
        return str(Path(self.disk_location) / "version_map.db")

    def open(self) -> None:
        """Opens connection to sqlite database."""
        self.conn = sqlite3.connect(self.dbname)
        self.cursor = self.conn.cursor()

    def close(self) -> None:
        """Closes connection to sqlite database."""
        if self.conn and self.cursor:
            self.cursor.close()
            self.conn.close()
            self.conn = None
            self.cursor = None

    def __enter__(self):
        """Opens connection to sqlite database."""
        self.open()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Closes connection to sqlite database."""
        self.close()

    def get_mapping_data(self):
        """
        Returns a version map associated with the specified checker. Also takes care of updating
        the data after the specified refresh duration
        """
        if self.cursor is None:
            return []
        self.cursor.execute(
            f"CREATE TABLE IF NOT EXISTS {self.table_name}(version TEXT , sourceId TEXT PRIMARY KEY)"
        )

        self.cursor.execute(
            f"CREATE TABLE IF NOT EXISTS {self.update_table_name} (datestamp DATETIME PRIMARY KEY)"
        )

        update_required: bool = False

        datestamp = self.cursor.execute(
            f"SELECT * FROM {self.update_table_name}"  # nosec
        ).fetchone()  # update_table_name validated in __init__

        if datestamp and type(datestamp) is tuple:
            # Updates if the difference between current time and the time of last update is greater than duration

            latest_update = datetime.fromtimestamp(datestamp[0])
            time_elapsed = datetime.now() - latest_update
            if time_elapsed.days >= self.duration:
                update_required = True

        if datestamp is None or update_required:
            # if update is required or database is empty, fetch and insert data into database
            self.cursor.execute(f"DELETE FROM {self.table_name}")  # nosec
            self.cursor.execute(f"DELETE FROM {self.update_table_name}")  # nosec
            self.cursor.execute(
                f"INSERT INTO {self.update_table_name} VALUES (?)",  # nosec
                (time.time(),),
            )

            for mapping in self.mapping_function():
                self.cursor.execute(
                    f"INSERT INTO {self.table_name} (version, sourceId) VALUES (?, ?)",  # nosec
                    (mapping[0], mapping[1]),
                )

        data = self.cursor.execute(
            f"SELECT * FROM {self.table_name}"  # nosec
        ).fetchall()  # table_name validated in __init__

        if self.conn is not None:
            self.conn.commit()
        return data
