# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import shutil

import aiohttp
from rich.progress import track

from cve_bin_tool.async_utils import FileIO
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.log import LOGGER


class Fetch_JSON_DB:
    """
    Downloads exported json files from mirror.
    """

    MAX_RETRIES = 2
    LOGGER = LOGGER.getChild("Fetch_JSON_DB")

    def __init__(
        self,
        mirror,
        cache_dir,
        error_mode: ErrorMode = ErrorMode.TruncTrace,
    ) -> None:
        self.root = cache_dir / "json_data"
        self.error_mode = error_mode
        self.connector = None
        self.mirror = mirror
        self.metadata = {}
        self.tasks = []
        self.download_failed = False
        self.failed_count = 0

    async def handle_download(self):
        self.connector = aiohttp.TCPConnector(limit_per_host=10)
        async with aiohttp.ClientSession(
            connector=self.connector, trust_env=True
        ) as session:
            await self.get_metdata(session)
            self.update_directory_structure()
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
            else:
                await self.download_metadata(session)

    def update_directory_structure(self):
        if self.root.is_dir():
            shutil.rmtree(self.root)
        self.root.mkdir()
        for key in self.metadata["db"]:
            dir = self.root / key
            if not dir.is_dir():
                dir.mkdir()

    def get_download_urls(self, session):
        for key in self.metadata["db"]:
            self.tasks.extend(
                [
                    session.get(f"{self.mirror}/{key}/{year}.json")
                    for year in self.metadata["db"][key]
                ]
            )

    def get_failed_downloads(self):
        db = {}
        for key in self.metadata["db"]:
            db[key] = []
            for year in self.metadata["db"][key]:
                if not (self.root / key / f"{year}.json").exists():
                    db[key].append(year)
        self.metadata["db"] = db

    async def download_files(self, tasks, description):
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
        resp = await session.get(f"{self.mirror}/metadata.json")
        resp = await resp.read()
        self.metadata = json.loads(resp)

    async def download_metadata(self, session):
        resp = await session.get(f"{self.mirror}/metadata.json")
        resp.raise_for_status()
        if resp.status == 200:
            data = await resp.read()
            async with FileIO(self.root / "metadata.json", "wb") as fd:
                await fd.write(data)
