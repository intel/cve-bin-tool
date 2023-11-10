# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from collections import defaultdict
from logging import Logger
from pathlib import Path

import defusedxml.ElementTree as ET
from lib4sbom.parser import SBOMParser
from packageurl import PackageURL

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.input_engine import TriageData
from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import ProductInfo, Remarks
from cve_bin_tool.validator import validate_cyclonedx, validate_spdx

from .swid_parser import SWIDParser


class SBOMManager:
    SBOMtype = ["spdx", "cyclonedx", "swid"]

    sbom_data: defaultdict[ProductInfo, TriageData]

    def __init__(
        self,
        filename: str,
        sbom_type: str = "spdx",
        logger: Logger | None = None,
        validate: bool = True,
    ):
        self.filename = filename
        self.sbom_data = defaultdict(dict)
        self.type = "unknown"
        if sbom_type in self.SBOMtype:
            self.type = sbom_type
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.validate = validate

        # Connect to the database
        self.cvedb = CVEDB(version_check=False)

    def scan_file(self) -> dict[ProductInfo, TriageData]:
        LOGGER.info(f"Processing SBOM {self.filename} of type {self.type.upper()}")
        modules = []
        try:
            if Path(self.filename).exists():
                if self.type == "swid":
                    swid = SWIDParser(self.validate)
                    modules = swid.parse(self.filename)
                else:
                    modules = self.parse_sbom()
        except (KeyError, FileNotFoundError, ET.ParseError) as e:
            LOGGER.debug(e, exc_info=True)

        LOGGER.debug(
            f"The number of modules identified in SBOM - {len(modules)}\n{modules}"
        )

        # Now process list of modules to create [vendor, product, version] tuples
        parsed_data: list[ProductInfo] = []
        for m in modules:
            # Using lower to normalize product names across databases
            product, version = m[0].lower(), m[1]
            if version != "":
                # Now add vendor to create product record....
                # print (f"Find vendor for {product} {version}")
                vendor_set = self.get_vendor(product)
                for vendor in vendor_set:
                    # if vendor is not None:
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

    def get_vendor(self, product: str) -> list:
        vendorlist: list[str] = []
        vendor_package_pair = self.cvedb.get_vendor_product_pairs(product)
        if vendor_package_pair != []:
            # To handle multiple vendors, return all combinations of product/vendor mappings
            for v in vendor_package_pair:
                vendor = v["vendor"]
                vendorlist.append(vendor)
        else:
            vendorlist.append("UNKNOWN")
        return vendorlist

    def parse_sbom(self):
        """parse SBOM, using PURL identifiers preferentially if found"""
        # Set up SBOM parser
        sbom_parser = SBOMParser(sbom_type=self.type)
        # Load SBOM
        sbom_parser.parse_file(self.filename)
        modules = []
        if self.validate and self.filename.endswith(".xml"):
            # Only for XML files
            if sbom_parser.get_type() == "spdx":
                valid_xml = validate_spdx(self.filename)
            else:
                valid_xml = validate_cyclonedx(self.filename)
            if not valid_xml:
                return modules
        packages = [x for x in sbom_parser.get_sbom()["packages"].values()]
        LOGGER.debug(f"Parsed SBOM {self.filename} {packages}")
        for package in packages:
            purl_found = False
            # If PURL record found, use this data in preference to package data
            ext_ref = package.get("externalreference")
            if ext_ref is not None:
                for ref in ext_ref:
                    if ref[1] == "purl":
                        # Process purl identifier
                        purl_info = PackageURL.from_string(ref[2]).to_dict()
                        if purl_info["name"] and purl_info["version"]:
                            modules.append([purl_info["name"], purl_info["version"]])
                            purl_found = True
            if not purl_found:
                if package.get("version") is not None:
                    modules.append([package["name"], package["version"]])
                else:
                    LOGGER.debug(f"No version found in {package}")
        LOGGER.debug(f"Parsed SBOM {self.filename} {modules}")
        return modules


if __name__ == "__main__":
    import sys

    file = sys.argv[1]
    sbom = SBOMManager(file)
    sbom.scan_file()
