# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

import sqlite3
from collections import defaultdict
from logging import Logger
from typing import DefaultDict, Dict, List, Optional

import defusedxml.ElementTree as ET

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.input_engine import TriageData
from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import ProductInfo, Remarks

from .cyclonedx_parser import CycloneParser
from .spdx_parser import SPDXParser
from .swid_parser import SWIDParser


class SBOMManager:

    SBOMtype = ["spdx", "cyclonedx", "swid"]

    sbom_data: DefaultDict[ProductInfo, TriageData]

    def __init__(
        self, filename: str, sbom_type: str = "spdx", logger: Optional[Logger] = None
    ):
        self.filename = filename
        self.sbom_data = defaultdict(dict)
        self.type = "unknown"
        if sbom_type in self.SBOMtype:
            self.type = sbom_type
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)

        # Connect to the database
        self.cvedb = CVEDB(version_check=False)

    def scan_file(self) -> Dict[ProductInfo, TriageData]:
        LOGGER.info(f"Processing SBOM {self.filename} of type {self.type.upper()}")
        try:
            if self.type == "spdx":
                spdx = SPDXParser()
                modules = spdx.parse(self.filename)
            elif self.type == "cyclonedx":
                cyclone = CycloneParser()
                modules = cyclone.parse(self.filename)
            elif self.type == "swid":
                swid = SWIDParser()
                modules = swid.parse(self.filename)
            else:
                modules = []
        except (KeyError, FileNotFoundError, ET.ParseError) as e:
            LOGGER.debug(e, exc_info=True)
            modules = []

        LOGGER.debug(
            f"The number of modules identified in SBOM - {len(modules)}\n{modules}"
        )

        # Now process list of modules to create [vendor, product, version] tuples
        parsed_data: List[ProductInfo] = []
        for m in modules:
            product, version = m[0], m[1]
            if version != "":
                # Now add vendor to create product record....
                # print (f"Find vendor for {product} {version}")
                vendor = self.get_vendor(product)
                if vendor is not None:
                    parsed_data.append(ProductInfo(vendor, product, version))
                    # print(vendor,product,version)

        for row in parsed_data:
            self.sbom_data[row]["default"] = {
                "remarks": Remarks.NewFound,
                "comments": "",
                "severity": "",
            }
            self.sbom_data[row]["paths"] = set(map(lambda x: x.strip(), "".split(",")))

        LOGGER.debug(f"SBOM Data {self.sbom_data}")
        return self.sbom_data

    def get_vendor(self, product: str) -> Optional[str]:
        self.cvedb.db_open()
        if not self.cvedb.connection:
            raise ConnectionError()
        self.cursor = self.cvedb.connection.cursor()
        get_vendor_request = "SELECT DISTINCT VENDOR FROM cve_range where PRODUCT=?"
        self.cursor.execute(get_vendor_request, [product])
        try:
            # If multiple unique vendors then shouldn't proceed....
            vendor = self.cursor.fetchone()[0]
            # print(f"{product} is produced by {vendor}")
        except (sqlite3.Error, TypeError) as e:
            LOGGER.debug(e, exc_info=True)
            vendor = None
        self.cvedb.db_close()
        return vendor


if __name__ == "__main__":
    import sys

    file = sys.argv[1]
    sbom = SBOMManager(file)
    sbom.scan_file()
