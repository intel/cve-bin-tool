# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json

from cve_bin_tool.parsers import Parser


class RParser(Parser):
    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
        self.filename = filename
        with open(self.filename) as fh:
            # parse the json structure for extracting product version pairs
            content = json.load(fh)
            for package in content["Packages"]:
                product = content["Packages"][package]["Package"]
                version = content["Packages"][package]["Version"]
                vendor = self.find_vendor(product, version)
                if vendor is not None:
                    yield from vendor
            self.logger.debug(f"Done scanning file: {self.filename}")
