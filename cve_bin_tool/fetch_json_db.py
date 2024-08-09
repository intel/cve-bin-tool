# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

import aiohttp
import gnupg
from rich.progress import track

from cve_bin_tool.async_utils import FileIO
from cve_bin_tool.error_handler import ERROR_CODES, ErrorMode, SigningError
from cve_bin_tool.log import LOGGER
from cve_bin_tool.version import HTTP_HEADERS


class Fetch_JSON_DB:
    """
    Downloads exported json files from mirror.
    """

    MAX_RETRIES = 2
    LOGGER = LOGGER.getChild("Fetch_JSON_DB")
    DIRECTORIES = [
        "cve_exploited",
        "cve_range",
        "cve_severity",
        "cve_metrics",
        "metrics",
    ]

    def __init__(
        self,
        mirror,
        cache_dir,
        pubkey,
        ignore_signature,
        log_signature_error,
        error_mode: ErrorMode = ErrorMode.TruncTrace,
    ) -> None:
        """
        Initialize the Fetch_JSON_DB instance.
        """
        self.root = cache_dir / "json_data"
        self.pubkey = pubkey
        self.ignore_signature = ignore_signature
        self.log_signature_error = log_signature_error
        self.error_mode = error_mode
        self.connector = None
        self.mirror = mirror
        self.metadata: dict[Any, Any] = {}
        self.is_signed = False
        self.tasks: list[str] = []
        self.download_failed = False
        self.failed_count = 0

    async def handle_download(self):
        """
        Manages the download process of JSON files from the mirror.
        """
        self.connector = aiohttp.TCPConnector(limit_per_host=10)
        async with aiohttp.ClientSession(
            connector=self.connector, headers=HTTP_HEADERS, trust_env=True
        ) as session:
            self.update_directory_structure()
            await self.get_metdata(session)
            if not self.ignore_signature and not self.is_signed:
                self.LOGGER.critical(
                    "The mirror data is not signed, the JSON data might have been tampared with"
                )
                self.LOGGER.critical(
                    "Use --ignore-sig flag to bypass signature verification"
                )
                if not self.log_signature_error:
                    self.cleanup_directory()
                    return ERROR_CODES[SigningError]
            elif self.is_signed:
                return_code = self.verify_signature()
                if bool(return_code) and not self.log_signature_error:
                    self.cleanup_directory()
                    return return_code
            self.get_download_urls(session)
            await self.download_files(self.tasks, "Downloading CVEs from mirror...")
            while self.download_failed and self.failed_count < self.MAX_RETRIES:
                self.failed_count += 1
                self.download_failed = False
                self.tasks = []
                self.get_failed_downloads()
                self.get_download_urls(session)
                await self.download_files(self.tasks, "Retrying failed downloads...")
            if self.download_failed:
                self.LOGGER.error("Failed to download CVEs from mirror")
                self.cleanup_directory()

    def cleanup_directory(self):
        """
        Cleans up the directory structure and removes temporary files.
        """
        for directory in self.DIRECTORIES:
            if (self.root / directory).exists():
                shutil.rmtree(self.root / directory)
        if (self.root / "metadata.asc").exists():
            Path.unlink(self.root / "metadata.asc")
        if (self.root / "metadata.json").exists():
            Path.unlink(self.root / "metadata.json")

    def update_directory_structure(self):
        """
        Updates the directory structure for storing downloaded files.
        """
        if self.root.is_dir():
            shutil.rmtree(self.root)
        self.root.mkdir()
        for key in self.DIRECTORIES:
            dir = self.root / key
            if not dir.is_dir():
                dir.mkdir()

    def get_download_urls(self, session):
        """
        Retrieves the URLs for downloading JSON files from the mirror.
        """
        for key in self.metadata["db"]:
            self.tasks.extend(
                [
                    session.get(f"{self.mirror}/{key}/{year}.json")
                    for year in self.metadata["db"][key]
                ]
            )
            if self.is_signed:
                self.tasks.extend(
                    [
                        session.get(f"{self.mirror}/{key}/{year}.asc")
                        for year in self.metadata["db"][key]
                    ]
                )

    def get_failed_downloads(self):
        """
        Identifies and logs unsuccessful download attempts.
        """
        db = {}
        for key in self.metadata["db"]:
            db[key] = []
            for year in self.metadata["db"][key]:
                if not (self.root / key / f"{year}.json").exists():
                    db[key].append(year)
        self.metadata["db"] = db

    async def download_files(self, tasks, description):
        """
        Downloads files asynchronously from the mirror.
        """
        # error_mode.value will only be greater than 1 if quiet mode.
        if self.error_mode.value > 1:
            total_tasks = len(tasks)
            iter_tasks = track(
                asyncio.as_completed(tasks),
                description,
                total=total_tasks,
            )
        else:
            iter_tasks = asyncio.as_completed(tasks)
        for task in iter_tasks:
            try:
                resp = await task
                if resp.status == 200:
                    request_url = str(resp.url)
                    filename = request_url.split("/")[len(request_url.split("/")) - 1]
                    directory = request_url.split("/")[len(request_url.split("/")) - 2]
                    data = await resp.read()
                    async with FileIO(self.root / directory / filename, "wb") as fd:
                        await fd.write(data)
            except Exception:
                self.download_failed = True

    async def get_metdata(self, session):
        """
        Fetches and stores metadata information from the mirror.
        """
        resp = await session.get(f"{self.mirror}/metadata.json")
        resp.raise_for_status()
        if resp.status == 200:
            data = await resp.read()
            self.metadata = json.loads(data)
            async with FileIO(self.root / "metadata.json", "wb") as fd:
                await fd.write(data)
        if self.ignore_signature:
            self.is_signed = False
            return
        resp = await session.get(f"{self.mirror}/metadata.asc")
        if resp.status == 200:
            self.is_signed = True
            data = await resp.read()
            async with FileIO(self.root / "metadata.asc", "wb") as fd:
                await fd.write(data)
        else:
            self.is_signed = False

    def verify_signature(self):
        """
        Checks the authenticity of downloaded metadata using signatures.
        """
        temp_gnupg_home = Path(tempfile.mkdtemp(prefix=".gnupg-"))
        gpg = gnupg.GPG(gnupghome=temp_gnupg_home)
        if self.pubkey:
            key_import_status = gpg.import_keys_file(self.pubkey)
        if not self.pubkey or key_import_status.results[0]["fingerprint"] is None:
            LOGGER.critical(
                "Something went wrong while importing the public key. Please try again!"
            )
            if temp_gnupg_home.exists():
                shutil.rmtree(temp_gnupg_home)
            return ERROR_CODES[SigningError]

        with open(self.root / "metadata.json", "rb") as fd:
            is_verified = gpg.verify_data(self.root / "metadata.asc", fd.read())
        if not is_verified:
            LOGGER.critical("Invalid signature detected!")
            if temp_gnupg_home.exists():
                shutil.rmtree(temp_gnupg_home)
            return ERROR_CODES[SigningError]
