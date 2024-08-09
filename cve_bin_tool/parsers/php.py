# NOTE: remains not complete


# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
"""Python script containing all functionalities related to parsing of php's composer.lock files."""
import json
import re

from cve_bin_tool.parsers import Parser


class PhpParser(Parser):
    """
    Parser for Php Composer.lock files.
    This parser is designed to parse Php Composer.lock and
    generate PURLs (Package URLs) for the listed packages.
    """

    PARSER_MATCH_FILENAMES = [
        "composer.lock",
    ]

    def __init__(self, cve_db, logger):
        """Initialize the PhpParser."""
        super().__init__(cve_db, logger)
        self.purl_pkg_type = "composer"

    def generate_purl(self, product, vendor="", qualifier={}, subpath=None):
        """Generates PURL after normalizing all components."""
        product = re.sub(r"[^a-zA-Z0-9._-]", "", product).lower()

        if not product:
            return None

        purl = super().generate_purl(
            product,
            vendor,
            qualifier,
            subpath,
        )

        return purl

    def run_checker(self, filename):
        """Process composer.lock file and extract product and dependency details"""
        self.filename = filename
        with open(self.filename) as fh:
            data = json.load(fh)
            packages = data["packages"] + data["packages-dev"]
            for package in packages:
                if "name" in package and "version" in package:
                    product = package["name"]
                    product = product.split("/")[1]
                    version = package["version"]
                    if version[0] == "v":
                        version = version[1:]
                    if "dev" in version:
                        continue
                    purl = self.generate_purl(product)
                    vendor = self.get_vendor(purl, product, version)
                    if vendor is not None:
                        yield from vendor
            self.logger.debug(f"Done scanning file: {self.filename}")
