# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from cve_bin_tool.parsers import Parser


class PerlParser(Parser):
    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
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
                vendor = self.find_vendor(dependency[0], dependency[1])
                if vendor is not None:
                    yield from vendor
        self.logger.debug(f"Done scanning file: {self.filename}")
