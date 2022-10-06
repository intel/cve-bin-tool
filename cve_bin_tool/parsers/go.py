# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from cve_bin_tool.parsers import Parser


class GoParser(Parser):
    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
        self.filename = filename
        with open(self.filename) as fh:
            lines = fh.readlines()
            packages = False
            for line in lines:
                # A go.mod file has requirements that look like this:
                # require (
                #     github.com/davecgh/go-spew v1.1.1
                #     github.com/evanphx/json-patch v4.12.0+incompatible
                # )
                line = line.strip()
                if line == "require (":
                    packages = True
                    continue
                if line == ")":
                    packages = False
                    continue
                if packages:
                    product = line.split(" ")[0].split("/")[-1]
                    version = line.split(" ")[1][1:].split("-")[0].split("+")[0]
                    vendor = self.find_vendor(product, version)
                    if vendor is not None:
                        yield from vendor
            self.logger.debug(f"Done scanning file: {self.filename}")
