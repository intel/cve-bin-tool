from __future__ import annotations

import zipfile
from io import BytesIO
from pathlib import Path

import aiohttp

from cve_bin_tool.data_sources import DISK_LOCATION_DEFAULT, Data_Source
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.log import LOGGER
from cve_bin_tool.version import HTTP_HEADERS


class PURL2CPE_Source(Data_Source):
    """Class to retrieve purl-cpe mapping database (PURL2CPE)"""

    SOURCE = "PURL2CPE"
    CACHEDIR = DISK_LOCATION_DEFAULT
    LOGGER = LOGGER.getChild("CVEDB")
    PURL2CPE_URL = "https://github.com/scanoss/purl2cpe/raw/main/purl2cpe.db.zip"

    def __init__(
        self, error_mode: ErrorMode = ErrorMode.TruncTrace, incremental_update=False
    ):
        self.cachedir = self.CACHEDIR
        self.purl2cpe_path = str(Path(self.cachedir) / "purl2cpe")
        self.source_name = self.SOURCE
        self.error_mode = error_mode
        self.incremental_update = incremental_update
        self.purl2cpe_url = self.PURL2CPE_URL
        self.session = None

    async def fetch_cves(self):
        """Fetches PURL2CPE database and places it in purl2cpe_path."""
        LOGGER.info("Getting PURL2CPE data...")

        if not Path(self.purl2cpe_path).exists():
            Path(self.purl2cpe_path).mkdir()

        if not self.session:
            connector = aiohttp.TCPConnector(limit_per_host=10)
            self.session = aiohttp.ClientSession(
                connector=connector, headers=HTTP_HEADERS, trust_env=True
            )

        try:
            response = await self.session.get(self.purl2cpe_url)
            if response.status == 200:
                data = await response.read()
                with zipfile.ZipFile(BytesIO(data), "r") as zip_ref:
                    zip_ref.extractall(self.purl2cpe_path)
            else:
                LOGGER.debug(f"Failed to download file. Status code: {response.status}")

        except Exception as e:
            LOGGER.debug(f"Error fetching PURL2CPE data: {e}")

        await self.session.close()
        self.session = None

    async def get_cve_data(self):
        """Fetches  PURL2CPE Database."""
        # skip if connection fails
        try:
            await self.fetch_cves()
        except Exception as e:
            LOGGER.debug(f"Error while fetching PURL2CPE Data: {e}")
            LOGGER.error("Unable to fetch PURL2CPE Data, skipping PURL2CPE.")
            if self.session is not None:
                await self.session.close()
            return (list(), list()), self.source_name

        if self.session is not None:
            await self.session.close()
        return (list(), list()), self.source_name
