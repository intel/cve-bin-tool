# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import subprocess
from re import MULTILINE, compile, search

from packaging.version import parse as parse_version

from cve_bin_tool.parsers import Parser
from cve_bin_tool.strings import parse_strings
from cve_bin_tool.util import ProductInfo, ScanInfo


class PythonRequirementsParser(Parser):
    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
        self.filename = filename
        try:
            output = subprocess.check_output(
                [
                    "pip3",
                    "install",
                    "-r",
                    self.filename,
                    "--dry-run",
                    "--ignore-installed",
                    "--report",
                    "-",
                    "--quiet",
                ],
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            self.logger.error(e.output)
            pip_version = str(subprocess.check_output(["pip3", "--version"]))
            # Output will look like:
            # pip 20.0.2 from /usr/lib/python3/dist-packages/pip (python 3.8)
            pip_version = pip_version.split(" ")[1]
            if parse_version(pip_version) < parse_version("22.2"):
                self.logger.error(
                    f"{filename} not scanned: pip --dry-run was unable to get package versions."
                )
                self.logger.error(
                    "pip version >= 22.2 is required to scan Python requirements files."
                )
        else:
            output = subprocess.check_output(
                [
                    "pip3",
                    "install",
                    "-r",
                    self.filename,
                    "--dry-run",
                    "--ignore-installed",
                    "--report",
                    "-",
                    "--quiet",
                ],
            )
            lines = json.loads(output)
            for line in lines["install"]:
                product = line["metadata"]["name"]
                version = line["metadata"]["version"]
                vendor = self.find_vendor(product, version)
                if vendor is not None:
                    yield from vendor
            self.logger.debug(f"Done scanning file: {self.filename}")


class PythonParser(Parser):
    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
        """
        This generator runs only for python packages.
        There are no actual checkers.
        The ProductInfo is computed without the help of any checkers from PKG-INFO or METADATA.
        """
        self.filename = filename
        lines = parse_strings(self.filename)
        lines = "\n".join(lines.splitlines()[:3])
        try:
            product = search(compile(r"^Name: (.+)$", MULTILINE), lines).group(1)
            version = search(compile(r"^Version: (.+)$", MULTILINE), lines).group(1)
            vendor_package_pair = self.cve_db.get_vendor_product_pairs(product)
            if vendor_package_pair != []:
                for pair in vendor_package_pair:
                    vendor = pair["vendor"]
                    file_path = self.filename
                    self.logger.debug(f"{file_path} is {vendor}.{product} {version}")
                    yield ScanInfo(ProductInfo(vendor, product, version), file_path)

        # There are packages with a METADATA file in them containing different data from what the tool expects
        except AttributeError:
            self.logger.debug(f"{filename} is an invalid METADATA/PKG-INFO")

        self.logger.debug(f"Done scanning file: {filename}")
