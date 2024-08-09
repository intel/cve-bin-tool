# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
"""Python script containing all functionalities related to parsing of javascript's package-lock.json files."""

import json
import re

from cve_bin_tool.parsers import Parser


class JavascriptParser(Parser):
    """Parser for javascript's package-lock.json and yarn.lock files"""

    PARSER_MATCH_FILENAMES = [
        "package-lock.json",
        "yarn.lock",
    ]

    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)
        self.purl_pkg_type = "npm"

    def generate_purl(self, product, vendor="", version="", qualifier={}, subpath=None):
        """Generates PURL after normalizing all components."""
        product = re.sub(r"[^a-zA-Z0-9._-]", "", product).lower()

        if not product:
            return None

        purl = super().generate_purl(
            product,
            vendor,
            version,
            qualifier,
            subpath,
        )

        return purl

    def get_package_name(self, name):
        """Returns npm package name by decomposing string"""
        return name.split("/")[-1] if "/" in name else name

    def run_checker(self, filename):
        """Determines the type of file and processes it accordingly"""
        self.filename = filename
        if filename.endswith("package-lock.json"):
            yield from self.process_package_lock(filename)
        elif filename.endswith("yarn.lock"):
            yield from self.process_yarn_lock(filename)
        self.logger.debug(f"Done scanning file: {self.filename}")

    def process_package_lock(self, filename):
        """Process package-lock.json file and extract product and dependency details"""
        with open(filename) as fh:
            data = json.load(fh)
            if "name" in data and "version" in data:
                product = data["name"]
                version = data["version"]
                purl = self.generate_purl(product)
                vendor = self.get_vendor(purl, product, version)
            else:
                vendor = None
            if vendor is not None:
                yield from vendor
            # npm generates a similarly named .package-lock.js file (note the starting `.`)
            # that will trigger this

            product_version_mapping = list()
            if data.get("lockfileVersion"):
                # Valid package-lock.json file contains lockfileVersion
                if isinstance(data, dict) and data.get("lockfileVersion", 0) >= 2:
                    for package_name, package_dependency in data["packages"].items():
                        product = self.get_package_name(package_name)
                        version = package_dependency.get("version")
                        product_version_mapping.append((product, version))

                        for n, v in package_dependency.get("requires", {}).items():
                            product = self.get_package_name(n)
                            version = v
                            if v == "*":
                                continue
                            product_version_mapping.append((product, version))
                else:
                    # Now process dependencies
                    for i in data["dependencies"]:
                        # To handle @actions/<product>: lines, extract product name from line
                        product = self.get_package_name(i)
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
                        product_version_mapping.append((product, version))

                        for n, v in data["dependencies"][i].get("requires", {}).items():
                            product = self.get_package_name(n)
                            version = v
                            if v == "*":
                                continue
                            product_version_mapping.append((product, version))

            for product, version in product_version_mapping:
                purl = self.generate_purl(product, "")
                vendor = self.get_vendor(purl, product, version)
                if vendor is not None:
                    yield from vendor

    def process_yarn_lock(self, filename):
        """Process yarn.lock file and extract product and dependency details
        Visit: https://classic.yarnpkg.com/en/docs/yarn-lock/ to better understand Yarn format
        """

        with open(filename) as fh:
            data = fh.read()

        # Regex pattern to match lines in the format:
        # package@version:
        #   version "version_number"
        product_version_mapping = list()
        pattern = re.compile(r'^"?([^@]+)@[^:]+:\n  version "([^"]+)"', re.MULTILINE)
        matches = pattern.findall(data)

        for match in matches:
            product = self.get_package_name(match[0])
            version = match[1]
            product_version_mapping.append((product, version))

        # Process each product-version pair to find vendor information
        for product, version in product_version_mapping:
            # Generate the PURL for the package
            purl = self.generate_purl(product, "", version)
            vendor, result = self.find_vendor_from_purl(purl, version)

            if not result:
                # If no vendor found using PURL, try to find vendor using product and version
                vendor = self.find_vendor(product, version)
            if vendor is not None:
                # Yield vendor information if found
                yield from vendor
