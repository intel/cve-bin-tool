# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import sqlite3
import time
from datetime import datetime

from cve_bin_tool.cvedb import DISK_LOCATION_DEFAULT


class VersionSignatureDb:
    """Methods for version signature data stored in sqlite"""

    def __init__(self, table_name, mapping_function, duration) -> None:
        """Set location on disk data cache will reside.
        Also sets the table name and refresh duration
        """
        self.table_name = table_name
        self.mapping_function = mapping_function
        self.disk_location = DISK_LOCATION_DEFAULT
        self.duration = duration
        self.conn = None
        self.cursor = None

    @property
    def dbname(self):
        """SQLite datebase file where the data is stored."""
        return os.path.join(self.disk_location, "version_map.db")

    def open(self):
        """Opens connection to sqlite database."""
        self.conn = sqlite3.connect(self.dbname)
        self.cursor = self.conn.cursor()

    def close(self):
        """Closes connection to sqlite database."""
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
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS {}(version TEXT , sourceId TEXT PRIMARY KEY)".format(
                self.table_name
            )
        )

        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS {} (datestamp DATETIME PRIMARY KEY)".format(
                "latest_update_" + self.table_name
            )
        )

        update_required: bool = False

        datestamp = self.cursor.execute(
            "SELECT * FROM {}".format("latest_update_" + self.table_name)
        ).fetchone()

        if datestamp and type(datestamp) is int:
            # Updates if the difference between current time and the time of last update is greater than duration

            latest_update = datetime.fromtimestamp(datestamp[0])
            time_elapsed = datetime.now() - latest_update
            if time_elapsed.days >= self.duration:
                update_required = True

        if datestamp is None or update_required:
            # if update is required or database is empty, fetch and insert data into database
            self.cursor.execute(f"DELETE FROM {self.table_name}")
            self.cursor.execute(
                "DELETE FROM {}".format("latest_update_" + self.table_name)
            )
            self.cursor.execute(
                "INSERT INTO {} VALUES (?)".format("latest_update_" + self.table_name),
                (time.time(),),
            )

            for mapping in self.mapping_function():
                self.cursor.execute(
                    "INSERT INTO {} (version, sourceId) VALUES (?, ?)".format(
                        self.table_name
                    ),
                    (mapping[0], mapping[1]),
                )

        data = self.cursor.execute(f"SELECT * FROM {self.table_name}").fetchall()
        self.conn.commit()
        return data
