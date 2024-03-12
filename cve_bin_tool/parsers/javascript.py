# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json

from cve_bin_tool.parsers import Parser


class JavascriptParser(Parser):
    """Parser for javascript's package-lock.json files"""

    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
        """Process package-lock.json file and extract product and dependency details"""
        self.filename = filename
        with open(self.filename) as fh:
            data = json.load(fh)
            if "name" in data and "version" in data:
                product = data["name"]
                version = data["version"]
                vendor = self.find_vendor(product, version)
            else:
                vendor = None
            if vendor is not None:
                yield from vendor

            # If there is no "dependencies" array then this file is likely not in a format we
            # can parse.  Log warning and abort.
            # npm generates a similarly named .package-lock.js file (note the starting `.`)
            # that will trigger this
            if "dependencies" not in data.keys():
                self.logger.warning(
                    f"Cannot parse {self.filename}: no dependencies array found."
                )
                return

            # Now process dependencies
            for i in data["dependencies"]:
                # To handle @actions/<product>: lines, extract product name from line
                product = i.split("/")[1] if "/" in i else i
                # Handle different formats. Either <product> : <version> or
                # <product>: {
                #       ...
                #       "version" : <version>
                #       ...
                #       }
                try:
                    version = data["dependencies"][i]["version"]
                except Exception:
                    # Cater for case when version field not present
                    version = data["dependencies"][i]
                vendor = self.find_vendor(product, version)
                if vendor is not None:
                    yield from vendor
                if "requires" in data["dependencies"][i]:
                    for r in data["dependencies"][i]["requires"]:
                        # To handle @actions/<product>: lines, extract product name from line
                        product = r.split("/")[1] if "/" in r else r
                        version = data["dependencies"][i]["requires"][r]
                        if version == "*":
                            continue
                        vendor = self.find_vendor(product, version)
                        if vendor is not None:
                            yield from vendor
            self.logger.debug(f"Done scanning file: {self.filename}")
