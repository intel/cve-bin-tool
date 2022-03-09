# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Retrieval access and of NVD entries using NVD Automatic CVE Retrieval

Parameter values and more information: https://nvd.nist.gov/developers/products
"""

import asyncio
import json
import math
import time
from datetime import datetime, timedelta, timezone
from logging import Logger
from typing import Dict, List, Union

import aiohttp
from rich.progress import Progress, track

from cve_bin_tool.async_utils import RateLimiter
from cve_bin_tool.error_handler import ErrorMode, NVDKeyError, NVDServiceError
from cve_bin_tool.log import LOGGER

FEED = "https://services.nvd.nist.gov/rest/json/cves/1.0"
NVD_CVE_STATUS = "https://nvd.nist.gov/rest/public/dashboard/statistics"

PAGESIZE = 2000
MAX_FAIL = 5
# Interval in seconds between successive requests
INTERVAL_PERIOD = 3


class NVD_API:
    def __init__(
        self,
        logger: Logger = LOGGER.getChild("NVD_API"),
        feed=FEED,
        session=None,
        page_size: int = PAGESIZE,
        max_fail: int = MAX_FAIL,
        interval: int = INTERVAL_PERIOD,
        error_mode: ErrorMode = ErrorMode.TruncTrace,
        incremental_update=False,
        api_key: str = "",
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.feed = feed
        self.session = session
        self.params: Dict = dict()
        self.page_size = page_size
        self.max_fail = max_fail
        self.interval = interval
        self.error_mode = error_mode
        self.incremental_update = incremental_update
        self.total_results = -1
        self.failed_count = 0
        self.all_cve_entries: List = []
        if api_key:
            self.params["apiKey"] = api_key

    @staticmethod
    def convert_date_to_nvd_date(date: datetime) -> str:
        """Returns a datetime string of NVD recognized date format"""
        utc_date = date.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S:%f")[:-3]
        return f"{utc_date} UTC-00:00"

    @staticmethod
    async def nvd_count_metadata(session):
        """Returns CVE Status count from NVD"""
        cve_count = {
            "Total": 0,
            "Rejected": 0,
            "Received": 0,
        }
        async with await session.get(
            NVD_CVE_STATUS,
            params={"reporttype": "countsbystatus"},
            raise_for_status=True,
        ) as response:
            data = await response.json()
            for key in data["vulnsByStatusCounts"]:
                cve_count[key["name"]] = int(key["count"])
        return cve_count

    async def get_nvd_params(
        self,
        time_of_last_update: Union[datetime, None] = None,
    ):
        """
        Initialize NVD request parameters
        """
        self.params["startIndex"] = 0
        self.params["resultsPerPage"] = self.page_size

        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=19)
            self.session = RateLimiter(
                aiohttp.ClientSession(connector=connector, trust_env=True)
            )

        self.logger.debug("Fetching metadata from NVD...")
        cve_count = await self.nvd_count_metadata(self.session)

        if "apiKey" in self.params:
            await self.validate_nvd_api()

        if time_of_last_update:
            # Fetch all the updated CVE entries from the modified date. Subtracting 2-minute offset for updating cve entries
            self.params["modStartDate"] = self.convert_date_to_nvd_date(
                time_of_last_update - timedelta(minutes=2)
            )
            self.params["modEndDate"] = self.convert_date_to_nvd_date(datetime.now())
            self.logger.info(
                f'Fetching updated CVE entries after {self.params["modStartDate"]}'
            )
            self.params["includeMatchStringChange"] = json.dumps(True)
            # Check modified strings inside CVEs as well
            with Progress() as progress:
                task = progress.add_task(
                    "Fetching incremental metadata from NVD...", total=1, start=False
                )
            while await self.load_nvd_request(start_index=0):
                progress.update(task)
            progress.update(task, advance=1)

        else:
            self.total_results = cve_count["Total"] - cve_count["Rejected"]
        self.logger.info(f"Adding {self.total_results} CVE entries")

    async def validate_nvd_api(self):
        """
        Validate NVD API
        """
        param_dict = self.params.copy()
        param_dict["startIndex"] = 0
        param_dict["resultsPerPage"] = 1
        try:
            self.logger.debug("Validating NVD API...")
            async with await self.session.get(
                self.feed, params=param_dict, raise_for_status=True
            ) as response:
                data = await response.json()
                if data.get("error", False):
                    self.logger.error(f"NVD API error: {data['error']}")
                    raise NVDKeyError(self.params["apiKey"])
        except NVDKeyError:
            # If the API key provided is invalid, delete from params
            # list and try the request again.
            self.logger.error("unset api key, retrying")
            del self.params["apiKey"]

    async def load_nvd_request(self, start_index):
        """Get single NVD request and update year_wise_data list which contains list of all CVEs"""

        param_dict = self.params.copy()
        param_dict["startIndex"] = start_index

        fetched_data = None
        while fetched_data is None:
            try:
                async with await self.session.get(
                    self.feed,
                    params=param_dict,
                    raise_for_status=True,
                ) as response:
                    if response.status == 200:
                        fetched_data = await response.json()

                        if start_index == 0:
                            # Update total results in case there is discrepancy between NVD dashboard and API
                            self.total_results = fetched_data["totalResults"]
                        self.all_cve_entries.extend(fetched_data["result"]["CVE_Items"])

                    elif response.status == 503:
                        raise NVDServiceError(self.params["modStartDate"])
                    else:
                        self.failed_count += 1
                        if self.failed_count == self.max_fail:
                            self.failed_count = 0
                            self.logger.info(
                                f"Pausing requests for {self.interval} seconds"
                            )
                            time.sleep(self.interval)
                        else:
                            time.sleep(1)

            except Exception as error:
                self.logger.debug(f"Failed to connect to NVD {error}")
                self.logger.debug(f"Pausing requests for {self.interval} seconds")
                self.failed_count += 1
                time.sleep(self.interval)

    async def get(self):
        """Calls load_nvd_request() multiple times to fetch all NVD feeds"""
        start_index = 1 if self.incremental_update else 0
        nvd_requests = [
            self.load_nvd_request(index * self.page_size)
            for index in range(
                start_index, 1 + int(math.ceil(self.total_results / self.page_size))
            )
        ]
        total_tasks = len(nvd_requests)
        # error_mode.value will only be greater than 1 if quiet mode.
        if self.error_mode.value > 1:
            iter_tasks = track(
                asyncio.as_completed(nvd_requests),
                description="Downloading Feeds from NVD...",
                total=total_tasks,
            )
        else:
            iter_tasks = asyncio.as_completed(nvd_requests)

        for task in iter_tasks:
            await task
