# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json

from cve_bin_tool.parsers import Parser


class PhpParser(Parser):
    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
        """Process package.lock file and extract product and dependency details"""
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
                    vendor = self.find_vendor(product, version)
                    if vendor is not None:
                        yield from vendor
            self.logger.debug(f"Done scanning file: {self.filename}")
