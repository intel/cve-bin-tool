# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import re

from cve_bin_tool.parsers import Parser


class RParser(Parser):
    """
    Parser implementation for R module files (renv.lock).

    This parser is designed to parse Go module files and generate Package URL (PURL) strings
    based on the modules and their dependencies listed in the file.

    Attributes:
        cve_db (CVEDB): The CVE database instance used for vulnerability information.
        logger (Logger): The logger instance for logging messages and debugging information.

    Methods:
        generate_purl(product, version, vendor):
            Generates PURL after normalizing all components.
        run_checker(filename):
            Parse the R module file and yield valid PURLs for the modules listed in the file.

    """

    PARSER_MATCH_FILENAMES = [
        "renv.lock",
    ]

    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)
        self.purl_pkg_type = "cran"

    def generate_purl(self, product, vendor="", qualifier={}, subpath=None):
        """Generates PURL after normalizing all components."""

        product = re.sub(r"[^a-zA-Z0-9.-]", "", product)

        if not re.match(r"^[a-zA-Z0-9_-]", product):
            return

        purl = super().generate_purl(
            product,
            vendor,
            qualifier,
            subpath,
        )

        return purl

    def run_checker(self, filename):
        """Parse the file and yield valid PURLs."""
        self.filename = filename
        with open(self.filename) as fh:
            # parse the json structure for extracting product version pairs
            content = json.load(fh)
            for package in content["Packages"]:
                product = content["Packages"][package]["Package"]
                version = content["Packages"][package]["Version"]
                purl = self.generate_purl(product)
                vendor = self.get_vendor(purl, product, version)
                if vendor is not None:
                    yield from vendor
            self.logger.debug(f"Done scanning file: {self.filename}")
