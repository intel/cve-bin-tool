# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import re

from cve_bin_tool.parsers import Parser


class RubyParser(Parser):
    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
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
                    vendor = self.find_vendor(product, version)
                    if vendor is not None:
                        yield from vendor
            self.logger.debug(f"Done scanning file: {self.filename}")
