# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Retrieval access and of NVD entries using NVD Automatic CVE Retrieval

Parameter values and more information: https://nvd.nist.gov/developers/products
"""
from __future__ import annotations

import asyncio
import math
import time
from datetime import datetime, timedelta, timezone
from logging import Logger

import aiohttp
from rich.progress import Progress, track

from cve_bin_tool.async_utils import RateLimiter
from cve_bin_tool.error_handler import ErrorMode, NVDKeyError, NVDServiceError
from cve_bin_tool.log import LOGGER
from cve_bin_tool.version import HTTP_HEADERS

FEED = "https://services.nvd.nist.gov/rest/json/cves/"
NVD_CVE_STATUS = "https://nvd.nist.gov/rest/public/dashboard/statistics"

PAGESIZE = 2000
MAX_FAIL = 5
# Interval in seconds between successive requests
INTERVAL_PERIOD = 6
# Number of simultaneous connections
MAX_HOSTS = 1
# 15 min timeout for requests
NVD_TIMEOUT = 900


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
        api_version: str = "2.0",
        max_hosts: int = MAX_HOSTS,
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.feed = feed
        self.session = session
        self.params: dict = dict()
        self.page_size = page_size
        self.max_fail = max_fail
        self.interval = interval
        self.max_hosts = max_hosts
        self.error_mode = error_mode
        self.incremental_update = incremental_update
        self.total_results = -1
        self.failed_count = 0
        self.all_cve_entries: list = []
        self.invalid_api = False
        self.api_version = api_version
        self.feed = f"{feed}{self.api_version}"
        self.api_key = api_key
        if self.api_key != "":
            if self.api_version == "2.0":
                # API key is passed as part of header
                self.header = HTTP_HEADERS
                self.header["apiKey"] = self.api_key

        else:
            # Because of rate limiting
            self.max_hosts = 1
            self.header = HTTP_HEADERS

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

    @staticmethod
    def convert_date_to_nvd_date_api2(date: datetime) -> str:
        """Returns a datetime string of NVD recognized date format"""
        utc_date = date.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        return f"{utc_date}"

    @staticmethod
    def get_reject_count_api2(fetched_data: dict) -> int:
        """Returns total rejected CVE count"""
        reject_count = 0
        if "cve" in fetched_data["vulnerabilities"]:
            all_cve_list = fetched_data["vulnerabilities"]["cve"]
            for cve_item in all_cve_list:
                if cve_item["descriptions"][0]["value"].startswith("** REJECT **"):
                    reject_count += 1
        return reject_count

    async def get_nvd_params(
        self,
        time_of_last_update: datetime | None = None,
    ):
        """
        Initialize NVD request parameters
        """
        self.params["startIndex"] = 0
        self.params["resultsPerPage"] = self.page_size

        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=self.max_hosts)
            connection_timeout = aiohttp.ClientTimeout(
                total=NVD_TIMEOUT,  # default value is 5 minutes, set to `None` for unlimited timeout
                sock_connect=10,  # How long to wait before an open socket allowed to connect
                sock_read=10,  # How long to wait with no data being read before timing out
            )
            self.session = RateLimiter(
                aiohttp.ClientSession(
                    connector=connector,
                    trust_env=True,
                    timeout=connection_timeout,
                    headers=self.header,
                )
            )

        self.logger.info("Fetching metadata from NVD...")
        cve_count = await self.nvd_count_metadata(self.session)
        self.logger.debug(f"NVD metadata {cve_count}")

        await self.validate_nvd_api()

        if self.invalid_api:
            if self.api_version == "1.0":
                self.logger.warning(
                    f'Unable to access NVD using provided API key: {self.params["apiKey"]}'
                )
            else:
                self.logger.warning(
                    f'Unable to access NVD using provided API key: {self.header["apiKey"]}'
                )
        else:
            if time_of_last_update:
                # Fetch all the updated CVE entries from the modified date. Subtracting 2-minute offset for updating cve entries
                if self.api_version == "2.0":
                    self.params["lastModStartDate"] = (
                        self.convert_date_to_nvd_date_api2(
                            time_of_last_update - timedelta(minutes=2)
                        )
                    )
                    self.params["lastModEndDate"] = self.convert_date_to_nvd_date_api2(
                        datetime.now()
                    )
                    self.logger.info(
                        f'Fetching updated CVE entries after {self.params["lastModStartDate"]}'
                    )

                # Check modified strings inside CVEs as well
                with Progress() as progress:
                    task = progress.add_task(
                        "Fetching incremental metadata from NVD...",
                        total=1,
                        start=False,
                    )
                while await self.load_nvd_request(start_index=0):
                    progress.update(task)
                progress.update(task, advance=1)

            else:
                self.total_results = cve_count["Total"] - cve_count["Rejected"]
            if self.total_results > 0:
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
                    if self.api_version == "1.0":
                        raise NVDKeyError(self.params["apiKey"])
                    else:
                        raise NVDKeyError(self.header["apiKey"])

        except aiohttp.ClientResponseError as client_err:
            self.logger.debug(f"Response {client_err}")
            self.invalid_api = True
            self.api_key = ""
        except NVDKeyError:
            # If the API key provided is invalid, delete from params
            # list and try the request again.
            self.logger.error("unset api key, retrying")
            if self.api_version == "2.0":
                del self.params["apiKey"]
                self.api_key = ""
            else:
                del self.header["apiKey"]
                self.api_key = ""

    async def load_nvd_request(self, start_index):
        """Get single NVD request and update year_wise_data list which contains list of all CVEs"""

        param_dict = self.params.copy()
        param_dict["startIndex"] = start_index

        fetched_data = None
        while fetched_data is None:
            try:
                self.logger.debug(f"Send request {self.feed} {param_dict}")
                async with await self.session.get(
                    self.feed,
                    params=param_dict,
                    raise_for_status=True,
                ) as response:
                    self.logger.debug(
                        f"Response received {response.status} for index {start_index}"
                    )
                    self.logger.debug(f"Header received {response.headers}")
                    if response.status == 200:
                        fetched_data = await response.json()
                        if start_index == 0:
                            # Update total results in case there is discrepancy between NVD dashboard and API
                            reject_count = self.get_reject_count_api2(fetched_data)
                            self.total_results = (
                                fetched_data["totalResults"] - reject_count
                            )
                        if self.api_version == "2.0":
                            if len(fetched_data["vulnerabilities"]) > 0:
                                self.all_cve_entries.extend(
                                    fetched_data["vulnerabilities"]
                                )

                    elif response.status == 503:
                        if self.api_version == "2.0":
                            raise NVDServiceError(self.params["lastModStartDate"])

                    else:
                        self.logger.info(f"Response code: {response.status}")
                        self.logger.info(f"Response content: {response.content}")
                        self.failed_count += 1
                        if self.failed_count == self.max_fail:
                            self.failed_count = 0
                            self.logger.info(
                                f"Pausing requests to NVD for {self.interval} seconds"
                            )
                            time.sleep(self.interval)
                        else:
                            time.sleep(1)
                if self.api_key == "":
                    # Back off due to rate limiting
                    self.logger.debug(
                        f"NVD Rate limiting - back off requests for {self.interval} seconds"
                    )
                    time.sleep(self.interval)
                else:
                    self.logger.debug(
                        f"NVD API Rate limiting - data from {start_index} processed"
                    )
                    time.sleep(1)

            except Exception as error:
                self.logger.debug(f"Connection with NVD - {error}")
                self.failed_count += 1
                if self.failed_count == self.max_fail:
                    # Back off
                    self.logger.debug("Backing off for 30 seconds")
                    time.sleep(30)
                    self.failed_count = 0
                else:
                    self.logger.debug(f"Pausing requests for {self.interval} seconds")
                    time.sleep(self.interval)

    async def get(self):
        """Calls load_nvd_request() multiple times to fetch all NVD feeds"""
        # Only attempt to download feeds if API params are valid and new CVEs are available to download
        if not self.invalid_api and self.total_results > 0:
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

            if self.api_key == "":
                # To accommodate rate limiting of the NVD requests
                # Estimate processing time assumes 10 seconds to process each request
                total_time = 10 * total_tasks
                time_unit = "seconds"
                # If more than 5 minutes, show time in number of minutes
                if total_time > 300:
                    time_unit = "minutes"
                    total_time = total_time % 60
                self.logger.info(
                    f"Estimated time to download CVE data from NVD: {total_time} {time_unit}"
                )

            for task in iter_tasks:
                await task
