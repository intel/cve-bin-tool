# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import re

from cve_bin_tool.parsers import Parser


class RustParser(Parser):
    """
    Parser implementation for Rust dependency files (Cargo.toml).

    This parser is designed to parse Rust dependency files (Cargo.toml) and generate
    Package URL (PURL) strings based on the packages and their versions listed in the file.

    Attributes:
        cve_db (CVEDB): The CVE database instance used for vulnerability information.
        logger (Logger): The logger instance for logging messages and debugging information.

    Methods:
        generate_purl(product, version, vendor):
            Generates PURL after normalizing all components.
        run_checker(filename):
            Parse the Rust dependency file and yield valid PURLs for the packages listed in the file.
    """

    PARSER_MATCH_FILENAMES = [
        "Cargo.lock",
    ]

    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)
        self.purl_pkg_type = "cargo"

    def generate_purl(self, product, vendor="", qualifier={}, subpath=None):
        """Generates PURL after normalizing all components."""

        product = re.sub(r"^[^a-zA-Z_]|[^a-zA-Z0-9_-]", "", product)

        if not re.match(r"^[a-zA-Z_]|[a-zA-Z0-9_-]", product):
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
        with open(filename) as fh:
            lines = fh.readlines()
            product = ""
            version = ""
            for line in lines:
                if line.split(" ")[0] == "name":
                    product = line.split(" ")[-1][1:-2]
                elif line.split(" ")[0] == "version":
                    version = line.split(" ")[-1][1:-2]
                else:
                    if product == "" and version == "":
                        continue

                    purl = self.generate_purl(product)
                    vendors = self.get_vendor(purl, product, version)
                    if vendors is not None:
                        yield from vendors
                    product = ""
                    version = ""
            self.logger.debug(f"Done scanning file: {self.filename}")
