# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import re

from cve_bin_tool.parsers import Parser


class GoParser(Parser):
    """
    Parser implementation for Go module files (go.mod).

    This parser is designed to parse Go module files and generate Package URL (PURL) strings
    based on the modules and their dependencies listed in the file.

    Attributes:
        cve_db (CVEDB): The CVE database instance used for vulnerability information.
        logger (Logger): The logger instance for logging messages and debugging information.

    Methods:
        generate_purl(product, version, vendor):
            Generates PURL after normalizing all components.
        run_checker(filename):
            Parse the Go module file and yield valid PURLs for the modules listed in the file.

    """

    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)
        self.purl_pkg_type = "golang"

    def generate_purl(self, product, version, vendor, qualifier={}, subpath=None):
        """Generates PURL after normalizing all components."""

        product = re.sub(r"[^a-zA-Z0-9_-]", "", product)
        version = re.sub(r"^[^a-zA-Z0-9]|[^a-zA-Z0-9.-]", "", version)
        vendor = re.sub(r"^[^a-zA-Z_]|[^a-zA-Z0-9_-]", "", vendor)

        if not re.match(r"^[a-zA-Z0-9_-]", product):
            return
        if vendor == "":
            vendor = "UNKNOWN"
        if version == "":
            version = "UNKNOWN"

        purl = super().generate_purl(
            product,
            version,
            vendor,
            qualifier,
            subpath,
        )

        return purl

    def run_checker(self, filename):
        """Parse the file and yield valid PURLs."""
        self.filename = filename
        with open(self.filename) as fh:
            lines = fh.readlines()
            packages = False
            for line in lines:
                # A go.mod file has requirements that look like this:
                # require (
                #     github.com/davecgh/go-spew v1.1.1
                #     github.com/evanphx/json-patch v4.12.0+incompatible
                # )
                line = line.strip()
                if line == "require (":
                    packages = True
                    continue
                if line == ")":
                    packages = False
                    continue
                if packages:
                    parts = line.split(" ")
                    if len(parts) >= 2:
                        product = line.split(" ")[0].split("/")[-1]
                        version = line.split(" ")[1][1:].split("-")[0].split("+")[0]
                        vendors = self.find_vendor(product, version)
                        if vendors is not None:
                            for v in vendors:
                                self.generate_purl(
                                    product, version, v.product_info.vendor
                                )
                            yield from vendors
            self.logger.debug(f"Done scanning file: {self.filename}")
