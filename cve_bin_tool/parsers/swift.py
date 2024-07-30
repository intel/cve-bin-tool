# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import re
from json.decoder import JSONDecodeError
from urllib.parse import urlparse

from cve_bin_tool.parsers import Parser


class SwiftParser(Parser):
    """
    Parser implementation for Swift dependency files (Package.resolved).

    This parser is designed to parse Swift dependencies files and generate Package URL (PURL) strings
    based on the modules and their dependencies listed in the file.

    Attributes:
        cve_db (CVEDB): The CVE database instance used for vulnerability information.
        logger (Logger): The logger instance for logging messages and debugging information.

    Methods:
        generate_purl(product, version, vendor):
            Generates PURL after normalizing all components.
        run_checker(filename):
            Parse the Swift dependency file and yield valid PURLs for the modules listed in the file.

    """

    PARSER_MATCH_FILENAMES = [
        "Package.resolved",
    ]

    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)
        self.purl_pkg_type = "swift"

    def generate_purl(self, product, vendor="", qualifier={}, subpath=None):
        """Generates PURL after normalizing all components."""

        product = re.sub(r"[^a-zA-Z0-9_-]", "", product)

        if not re.match(r"[a-zA-Z0-9_-]", product):
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
            try:
                content = json.load(fh)
            except JSONDecodeError as e:
                self.logger.debug(f"Error occurred while parsing {filename}: {e}")
                return
            for package in content["object"]["pins"]:
                product = package["package"]
                version = package["state"]["version"]
                repository_url = package.get("repositoryURL", None)
                domain = None
                if repository_url:
                    parse = urlparse(repository_url)
                    domain = parse.netloc
                self.logger.debug(domain)

                purl = self.generate_purl(product)
                vendors = self.get_vendor(purl, product, version)
                if vendors is not None:
                    yield from vendors
            self.logger.debug(f"Done scanning file: {self.filename}")
