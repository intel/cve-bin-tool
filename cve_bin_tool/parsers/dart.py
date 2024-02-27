# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import yaml

from cve_bin_tool.parsers import Parser


class DartParser(Parser):
    """
    A parser class for handling pubspec.lock file
    based on: https://dart.dev/tools/pub/pubspec
    https://dart.dev/overview
    """

    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

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
                vendor = self.find_vendor(product, version)
                if vendor:
                    yield from vendor
        self.logger.debug(f"Done scanning file: {self.filename}")
