# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import re

import yaml

from cve_bin_tool.parsers import Parser


class DartParser(Parser):
    """
    A parser class for handling pubspec.lock file
    based on: https://dart.dev/tools/pub/pubspec
    https://dart.dev/overview
    """

    PARSER_MATCH_FILENAMES = [
        "pubspec.lock",
    ]

    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)
        self.purl_pkg_type = "pub"

    def generate_purl(self, product, vendor="", qualifier={}, subpath=None):
        """
        Generates PURL after normalizing all components.
        pubspec: https://dart.dev/tools/pub/pubspec#name
        purl-spec for pub: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#pub
        """
        # Normalize product for Dart packages
        product = re.sub(r"[^a-zA-Z0-9_]", "", product).lower()
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
        """
        Process pubspec.lock file and extract product and version details
        """
        self.filename = filename
        with open(self.filename) as file:
            data = yaml.safe_load(file)
            for package_name, package_detail in data.get("packages", {}).items():
                product = package_name
                version = package_detail.get("version").replace('"', "")
                purl = self.generate_purl(product)
                vendor = self.get_vendor(purl, product, version)
                if vendor:
                    yield from vendor
        self.logger.debug(f"Done scanning file: {self.filename}")
