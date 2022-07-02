# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from abc import ABC, abstractmethod
from pathlib import Path

USER_HOME = Path("~")

# database defaults
DISK_LOCATION_DEFAULT = str(USER_HOME.expanduser() / ".cache" / "cve-bin-tool")
DISK_LOCATION_BACKUP = str(USER_HOME.expanduser() / ".cache" / "cve-bin-tool-backup")
DBNAME = "cve.db"
OLD_CACHE_DIR = str(USER_HOME.expanduser() / ".cache" / "cvedb")
NVD_FILENAME_TEMPLATE = "nvdcve-1.1-{}.json.gz"


class Data_Source(ABC):
    @abstractmethod
    def get_cve_data():
        pass
