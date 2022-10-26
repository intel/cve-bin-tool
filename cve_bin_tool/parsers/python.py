# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import subprocess
from re import MULTILINE, compile, search

from cve_bin_tool.parsers import Parser
from cve_bin_tool.strings import parse_strings
from cve_bin_tool.util import ProductInfo, ScanInfo


class PythonRequirementsParser(Parser):
    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
        self.filename = filename
        lines = json.loads(
            subprocess.check_output(
                [
                    "pip3",
                    "install",
                    "-r",
                    self.filename,
                    "--dry-run",
                    "--ignore-installed",
                    "--report",
                    "-",
                    "--quiet",
                ]
            )
        )
        for line in lines["install"]:
            product = line["metadata"]["name"]
            version = line["metadata"]["version"]
            vendor = self.find_vendor(product, version)
            if vendor is not None:
                yield from vendor
        self.logger.debug(f"Done scanning file: {self.filename}")


class PythonParser(Parser):
    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

    def find_vendor(self, product, version):
        vendor_package_pair = self.cve_db.get_vendor_product_pairs(product)
        if vendor_package_pair != []:
            vendor = vendor_package_pair[0]["vendor"]
            file_path = self.filename
            self.logger.info(f"{file_path} is {product} {version}")
            return ScanInfo(ProductInfo(vendor, product, version), file_path)
        return None

    def run_checker(self, filename):
        """
        This generator runs only for python packages.
        There are no actual checkers.
        The ProductInfo is computed without the help of any checkers from PKG-INFO or METADATA.
        """
        self.filename = filename
        lines = parse_strings(self.filename)
        lines = "\n".join(lines.splitlines()[:3])
        try:
            product = search(compile(r"^Name: (.+)$", MULTILINE), lines).group(1)
            version = search(compile(r"^Version: (.+)$", MULTILINE), lines).group(1)
            product_info = self.find_vendor(product, version)
            if product_info is not None:
                yield product_info

        # There are packages with a METADATA file in them containing different data from what the tool expects
        except AttributeError:
            self.logger.debug(f"{filename} is an invalid METADATA/PKG-INFO")

        self.logger.debug(f"Done scanning file: {filename}")
