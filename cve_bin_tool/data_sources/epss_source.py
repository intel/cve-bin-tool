# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import csv
import gzip
import logging
import os
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path

import aiohttp

from cve_bin_tool.data_sources import DISK_LOCATION_BACKUP, DISK_LOCATION_DEFAULT
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.version import HTTP_HEADERS

logging.basicConfig(level=logging.DEBUG)


class Epss_Source:
    """Data source for downloading and storing epss data"""

    SOURCE = "EPSS"
    CACHEDIR = DISK_LOCATION_DEFAULT
    BACKUPCACHEDIR = DISK_LOCATION_BACKUP
    LOGGER = logging.getLogger().getChild("CVEDB")
    DATA_SOURCE_LINK = "https://epss.cyentia.com/epss_scores-current.csv.gz"

    def __init__(self, error_mode=ErrorMode.TruncTrace):
        self.epss_data = None
        self.error_mode = error_mode
        self.cachedir = self.CACHEDIR
        self.backup_cachedir = self.BACKUPCACHEDIR
        self.epss_path = str(Path(self.cachedir) / "epss")
        self.file_name = os.path.join(self.epss_path, "epss_scores-current.csv")
        self.epss_metric_id = None
        self.source_name = self.SOURCE

    async def update_epss(self, cursor):
        """
        Updates the EPSS data by downloading and parsing the CSV file.
        Returns:
            list: A list of tuples containing the parsed EPSS data.
                  - CVE ID
                  - Source (always "EPSS" in this case)
                  - EPSS score
                  - EPSS percentile
        """
        self.LOGGER.debug("Fetching EPSS data...")

        self.EPSS_id_finder(cursor)
        await self.download_epss_data()
        self.epss_data = self.parse_epss_data()
        return self.epss_data

    async def download_epss_data(self):
        """Downloads the EPSS CSV file and saves it to the local filesystem.
        The download is only performed if the file is older than 24 hours.
        """
        os.makedirs(self.epss_path, exist_ok=True)
        # Check if the file exists
        if os.path.exists(self.file_name):
            # Get the modification time of the file
            modified_time = os.path.getmtime(self.file_name)
            last_modified = datetime.fromtimestamp(modified_time)

            # Calculate the time difference between now and the last modified time
            time_difference = datetime.now() - last_modified

            # Check if the file is older than 24 hours
            if time_difference > timedelta(hours=24):
                try:
                    async with aiohttp.ClientSession(
                        headers=HTTP_HEADERS, trust_env=True
                    ) as session:
                        async with session.get(self.DATA_SOURCE_LINK) as response:
                            response.raise_for_status()
                            self.LOGGER.info("Getting EPSS data...")
                            decompressed_data = gzip.decompress(await response.read())

                    # Save the downloaded data to the file
                    with open(self.file_name, "wb") as file:
                        file.write(decompressed_data)

                except aiohttp.ClientError as e:
                    self.LOGGER.error(f"An error occurred during updating epss {e}")

            else:
                self.LOGGER.info(
                    "Utilizing the latest cache of EPSS data, which is less than 24 hours old."
                )

        else:
            try:
                async with aiohttp.ClientSession(
                    headers=HTTP_HEADERS, trust_env=True
                ) as session:
                    async with session.get(self.DATA_SOURCE_LINK) as response:
                        response.raise_for_status()
                        self.LOGGER.info("Getting EPSS data...")
                        decompressed_data = gzip.decompress(await response.read())

                # Save the downloaded data to the file
                with open(self.file_name, "wb") as file:
                    file.write(decompressed_data)

            except aiohttp.ClientError as e:
                self.LOGGER.error(f"An error occurred during downloading epss {e}")

    def EPSS_id_finder(self, cursor):
        """Search for metric id in EPSS table"""
        query = """
        SELECT metrics_id FROM metrics
        WHERE metrics_name = "EPSS"
        """
        cursor.execute(query)
        self.epss_metric_id = cursor.fetchall()[0][0]

    def parse_epss_data(self, file_path=None):
        """Parse epss data from the file path given and return the parse data"""
        parsed_data = []
        if file_path is None:
            file_path = self.file_name

        with open(file_path) as file:
            # Read the content of the CSV file
            decoded_data = file.read()

        # Create a CSV reader to read the data from the decoded CSV content
        reader = csv.reader(StringIO(decoded_data), delimiter=",")

        # Skip the first line (header) and the next line (empty line)
        next(reader)
        next(reader)
        # Parse the data from the remaining rows
        for row in reader:
            cve_id, epss_score, epss_percentile = row[:3]
            parsed_data.append(
                (cve_id, self.epss_metric_id, epss_score, epss_percentile)
            )
        return parsed_data

    async def get_cve_data(self):
        """Gets EPSS data.
        This function is so that the epss source matches the others api-wise to make for
        easier disabling/enabling.

        returns (data, "EPSS") so that the source can be identified for storing data
        """

        try:
            await self.update_epss()
        except Exception as e:
            self.LOGGER.debug(f"Error while fetching EPSS data: {e}")
            self.LOGGER.error("Unable to fetch EPSS, skipping EPSS.")

        return self.epss_data, self.SOURCE
