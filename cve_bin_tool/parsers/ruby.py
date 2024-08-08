# Copyright (C) 2024 Intel Corporation


# SPDX-License-Identifier: GPL-3.0-or-later

import re

from cve_bin_tool.parsers import Parser


class RubyParser(Parser):
    """
    Parser implementation for Ruby gem files (Gemfile.lock).

    This parser is designed to parse Ruby gem files and generate Package URL (PURL) strings
    based on the modules and their dependencies listed in the file.

    Attributes:
        cve_db (CVEDB): The CVE database instance used for vulnerability information.
        logger (Logger): The logger instance for logging messages and debugging information.

    Methods:
        generate_purl(product, version, vendor):
            Generates PURL after normalizing all components.
        run_checker(filename):
            Parse the Ruby gem file and yield valid PURLs for the modules listed in the file.

    """

    PARSER_MATCH_FILENAMES = [
        "Gemfile.lock",
    ]

    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)
        self.purl_pkg_type = "gem"

    def generate_purl(self, product, vendor="", qualifier={}, subpath=None):
        """Generates PURL after normalizing all components."""

        product = re.sub(r"^[^a-z]|[^a-z0-9_-]", "", product)

        if not re.match(r"^[a-z]|[a-z0-9_-]", product):
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
            packages = False
            for line in lines:
                if line.strip() == "GEM":
                    packages = True
                    continue
                if line.strip() == "":
                    packages = False
                    continue
                if (
                    packages
                    and len(line.strip().split()) > 1
                    and re.match(r"\([0-9]+\.[0-9]+\.[0-9]+\)", line.strip().split()[1])
                ):
                    product = line.strip().split()[0]
                    version = line.strip().split("(")[1][:-1]
                    purl = self.generate_purl(product)
                    vendors = self.get_vendor(purl, product, version)
                    if vendors is not None:
                        yield from vendors
            self.logger.debug(f"Done scanning file: {self.filename}")
