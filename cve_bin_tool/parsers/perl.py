# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
"""Python script containing all functionalities related to parsing of perl's cpan files."""
import re

from cve_bin_tool.parsers import Parser


class PerlParser(Parser):
    """Parser for perl's cpan files"""

    PARSER_MATCH_FILENAMES = [
        "cpanfile",
    ]

    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)
        self.purl_pkg_type = "cpan"

    def generate_purl(self, product, vendor="", qualifier={}, subpath=None):
        """Generates PURL after normalizing all components."""
        # Normalize product and vendor for Perl packages
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
        """Process cpan file and extract dependency details"""
        self.filename = filename
        with open(self.filename) as fh:
            data = fh.readlines()
            # Split each line into tokens and find dependencies
            dependencies = []
            for line in data:
                tokens = line.split()
                if len(tokens) >= 4 and tokens[0] == "requires" and tokens[2] == "=>":
                    dependencies.append(
                        (
                            tokens[1].strip('"').split("::")[-1],
                            tokens[3].strip("'").strip(";").strip('"'),
                        )
                    )
                elif len(tokens) >= 1 and tokens[0] == "requires":
                    name = (tokens[1].strip('"').split("::")[-1],)
                    self.logger.debug(f"Dependency with no version information: {name}")

            # Print the extracted dependencies
            for dependency in dependencies:
                product = dependency[0]
                version = dependency[1]
                purl = self.generate_purl(product)
                vendor = self.get_vendor(purl, product, version)
                if vendor is not None:
                    yield from vendor
        self.logger.debug(f"Done scanning file: {self.filename}")
