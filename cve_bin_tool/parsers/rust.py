# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from cve_bin_tool.parsers import Parser


class RustParser(Parser):
    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
        self.filename = filename
        with open(filename) as fh:
            # parse the multiline name and version format
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
                    vendor = self.find_vendor(product, version)
                    product = ""
                    version = ""
                    if vendor is not None:
                        yield from vendor
            self.logger.debug(f"Done scanning file: {self.filename}")
