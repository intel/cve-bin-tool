# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import subprocess
import sys
from logging import Logger
from re import MULTILINE, compile, search
from typing import Iterator

import defusedxml.ElementTree as ET

from cve_bin_tool.checkers import Checker
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.egg_updater import IS_DEVELOP, update_egg
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.extractor import Extractor, TempDirExtractorContext
from cve_bin_tool.file import is_binary
from cve_bin_tool.log import LOGGER
from cve_bin_tool.strings import Strings
from cve_bin_tool.util import DirWalk, ProductInfo, ScanInfo, inpath
from cve_bin_tool.validator import validate_pom

if sys.version_info >= (3, 8):
    from importlib import metadata as importlib_metadata
else:
    import importlib_metadata


class InvalidFileError(Exception):
    """Filepath is invalid for scanning."""


class VersionScanner:
    """ "Scans files for CVEs using CVE checkers"""

    CHECKER_ENTRYPOINT = "cve_bin_tool.checker"

    def __init__(
        self,
        should_extract: bool = False,
        exclude_folders: list[str] = [],
        checkers: dict[str, type[Checker]] | None = None,
        logger: Logger | None = None,
        error_mode: ErrorMode = ErrorMode.TruncTrace,
        score: int = 0,
        validate: bool = True,
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        # Update egg if installed in development mode
        if IS_DEVELOP():
            self.logger.debug("Updating egg_info")
            update_egg()

        # Load checkers if not given
        self.checkers = checkers or self.load_checkers()
        self.score = score
        self.total_scanned_files = 0
        self.exclude_folders = exclude_folders + [".git"]

        self.walker = DirWalk(
            folder_exclude_pattern=";".join(
                exclude if exclude.endswith("*") else exclude + "*"
                for exclude in exclude_folders
            )
        ).walk
        self.should_extract = should_extract
        self.file_stack: list[str] = []
        self.error_mode = error_mode
        self.cve_db = CVEDB()
        self.validate = validate
        # self.logger.info("Checkers loaded: %s" % (", ".join(self.checkers.keys())))

    @classmethod
    def load_checkers(cls) -> dict[str, type[Checker]]:
        """Loads CVE checkers"""
        checkers = dict(
            map(
                lambda checker: (checker.name, checker.load()),
                importlib_metadata.entry_points()[cls.CHECKER_ENTRYPOINT],
            )
        )
        return checkers

    @classmethod
    def available_checkers(cls) -> list[str]:
        checkers = importlib_metadata.entry_points()[cls.CHECKER_ENTRYPOINT]
        checker_list = [item.name for item in checkers]
        return checker_list

    def remove_skiplist(self, skips: list[str]) -> None:
        # Take out any checkers that are on the skip list
        # (string of comma-delimited checker names)
        skiplist = skips
        for skipme in skiplist:
            if skipme in self.checkers:
                del self.checkers[skipme]
                self.logger.debug(f"Skipping checker: {skipme}")
            else:
                self.logger.error(f"Checker {skipme} is not a valid checker name")

    def print_checkers(self) -> None:
        self.logger.info(f'Checkers: {", ".join(self.checkers.keys())}')

    def number_of_checkers(self) -> int:
        return len(self.checkers)

    def is_executable(self, filename: str) -> tuple[bool, str | None]:
        """check if file is an ELF binary file"""

        output: str | None = None
        if inpath("file"):
            # use system file if available (for performance reasons)
            output = subprocess.check_output(["file", filename]).decode(
                sys.stdout.encoding
            )

            if "cannot open" in output:
                self.logger.warning(f"Unopenable file {filename} cannot be scanned")
                return False, None

            if (
                ("LSB " not in output)
                and ("LSB shared" not in output)
                and ("LSB executable" not in output)
                and ("PE32 executable" not in output)
                and ("PE32+ executable" not in output)
                and ("Mach-O" not in output)
                and ("PKG-INFO: " not in output)
                and ("METADATA: " not in output)
                and ("pom.xml" not in output)
                and ("package-lock.json" not in output)
            ):
                return False, None
        # otherwise use python implementation of file
        elif not is_binary(filename):
            return False, None

        return True, output

    def parse_strings(self, filename: str) -> str:
        """parse binary file's strings"""

        if inpath("strings"):
            # use "strings" on system if available (for performance)
            lines = subprocess.check_output(["strings", filename]).decode("utf-8")
        else:
            # Otherwise, use python implementation
            s = Strings(filename)
            lines = s.parse()
        return lines

    def scan_file(self, filename: str) -> Iterator[ScanInfo]:
        """Scans a file to see if it contains any of the target libraries,
        and whether any of those contain CVEs"""

        self.logger.debug(f"Scanning file: {filename}")
        self.total_scanned_files += 1

        # Do not try to scan symlinks
        if os.path.islink(filename):
            return None

        # Ensure filename is a file
        if not os.path.isfile(filename):
            self.logger.debug(f"Invalid file {filename} cannot be scanned")
            return None

        # check if it's an ELF binary file
        is_exec, output = self.is_executable(filename)

        if not is_exec:
            return None

        # parse binary file's strings
        lines = self.parse_strings(filename)

        # Check for Java package
        if output and "pom.xml" in output:
            yield from self.run_java_checker(filename)

        # Javascript checker
        if output and "package-lock.json" in output:
            yield from self.run_js_checker(filename)

        #  If python package then strip the lines to avoid detecting other product strings
        if output and ("PKG-INFO: " in output or "METADATA: " in output):
            py_lines = "\n".join(lines.splitlines()[:3])
            yield from self.run_python_package_checkers(filename, py_lines)

        yield from self.run_checkers(filename, lines)

    def find_java_vendor(
        self, product: str, version: str
    ) -> tuple[ProductInfo, str] | tuple[None, None]:
        """Find vendor for Java product"""
        vendor_package_pair = self.cve_db.get_vendor_product_pairs(product)
        # If no match, try alternative product name.
        # Apache product names are stored as A_B in NVD database but often called A-B
        # Some packages have -parent appended to product which is not in NVD database
        if vendor_package_pair == [] and "-" in product:
            self.logger.debug(f"Try alternative product {product}")
            # Remove parent appendage
            if "-parent" in product:
                product = product.replace("-parent", "")
            product = product.replace("-", "_")
            vendor_package_pair = self.cve_db.get_vendor_product_pairs(product)
        if vendor_package_pair != []:
            vendor = vendor_package_pair[0]["vendor"]
            file_path = "".join(self.file_stack)
            self.logger.debug(f"{file_path} {product} {version} by {vendor}")
            return ProductInfo(vendor, product, version), file_path
        return None, None

    def run_java_checker(self, filename: str) -> Iterator[ScanInfo]:
        """Process maven pom.xml file and extract product and dependency details"""
        continue_processing = True
        if self.validate:
            continue_processing = validate_pom(filename)
            self.logger.debug(f"Validation of {filename} - {continue_processing}")
        if continue_processing:
            tree = ET.parse(filename)
            # Find root element
            root = tree.getroot()
            # Extract schema
            schema = root.tag[: root.tag.find("}") + 1]
            parent = root.find(schema + "parent")
            version = None
            product = None
            file_path = "".join(self.file_stack)
            # Parent tag is optional.
            if parent is None:
                product = root.find(schema + "artifactId").text
                version = root.find(schema + "version").text
            if version is None and parent is not None:
                version = parent.find(schema + "version").text

            # If no version has been found, set version to UNKNOWN
            if version is None:
                version = "UNKNOWN"

            # Check valid version identifier (i.e. starts with a digit)
            if not version[0].isdigit():
                self.logger.debug(f"Invalid {version} detected in {filename}")
                version = None
            if product is None and parent is not None:
                product = parent.find(schema + "artifactId").text
            if product is not None and version is not None:
                product_info, file_path = self.find_java_vendor(product, version)
                if file_path is not None:
                    yield ScanInfo(product_info, file_path)

            # Scan for any dependencies referenced in file
            dependencies = root.find(schema + "dependencies")
            if dependencies is not None:
                for dependency in dependencies.findall(schema + "dependency"):
                    product = dependency.find(schema + "artifactId")
                    if product is not None:
                        version = dependency.find(schema + "version")
                        if version is not None:
                            version = version.text
                            self.logger.debug(f"{file_path} {product.text} {version}")
                            if version[0].isdigit():
                                # Valid version identifier
                                product_info, file_path = self.find_java_vendor(
                                    product.text, version
                                )
                                if file_path is not None:
                                    yield ScanInfo(product_info, file_path)

        self.logger.debug(f"Done scanning file: {filename}")

    def find_js_vendor(self, product: str, version: str) -> list[ScanInfo] | None:
        """Find vendor for Javascript product"""
        if version == "*":
            return None
        vendor_package_pair = self.cve_db.get_vendor_product_pairs(product)
        vendorlist: list[ScanInfo] = []
        if vendor_package_pair != []:
            # To handle multiple vendors, return all combinations of product/vendor mappings
            for v in vendor_package_pair:
                vendor = v["vendor"]
                file_path = "".join(self.file_stack)
                # Tidy up version string
                if "^" in version:
                    version = version[1:]
                self.logger.debug(f"{file_path} {product} {version} by {vendor}")
                vendorlist.append(
                    ScanInfo(ProductInfo(vendor, product, version), file_path)
                )
            return vendorlist if len(vendorlist) > 0 else None
        return None

    def run_js_checker(self, filename: str) -> Iterator[ScanInfo]:
        """Process package-lock.json file and extract product and dependency details"""
        fh = open(filename)
        data = json.load(fh)
        product = data["name"]
        version = data["version"]
        vendor = self.find_js_vendor(product, version)
        if vendor is not None:
            yield from vendor
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
            vendor = self.find_js_vendor(product, version)
            if vendor is not None:
                yield from vendor
            if "requires" in data["dependencies"][i]:
                for r in data["dependencies"][i]["requires"]:
                    # To handle @actions/<product>: lines, extract product name from line
                    product = r.split("/")[1] if "/" in r else r
                    version = data["dependencies"][i]["requires"][r]
                    vendor = self.find_js_vendor(product, version)
                    if vendor is not None:
                        yield from vendor
        self.logger.debug(f"Done scanning file: {filename}")

    def run_python_package_checkers(
        self, filename: str, lines: str
    ) -> Iterator[ScanInfo]:
        """
        This generator runs only for python packages.
        There are no actual checkers.
        The ProductInfo is computed without the help of any checkers from PKG-INFO or METADATA.
        """
        try:
            product = search(compile(r"^Name: (.+)$", MULTILINE), lines).group(1)
            version = search(compile(r"^Version: (.+)$", MULTILINE), lines).group(1)

            cve_db = CVEDB()
            vendor_package_pair = cve_db.get_vendor_product_pairs(product)

            if vendor_package_pair != []:
                vendor = vendor_package_pair[0]["vendor"]
                file_path = "".join(self.file_stack)

                self.logger.info(f"{file_path} is {product} {version}")

                yield ScanInfo(ProductInfo(vendor, product, version), file_path)

        # There are packages with a METADATA file in them containing different data from what the tool expects
        except AttributeError:
            self.logger.debug(f"{filename} is an invalid METADATA/PKG-INFO")

        self.logger.debug(f"Done scanning file: {filename}")

    def run_checkers(self, filename: str, lines: str) -> Iterator[ScanInfo]:
        # tko
        for (dummy_checker_name, checker) in self.checkers.items():
            checker = checker()
            result = checker.get_version(lines, filename)
            # do some magic so we can iterate over all results, even the ones that just return 1 hit
            if "is_or_contains" in result:
                results = [dict()]
                results[0] = result
            else:
                results = result

            for result in results:
                if "is_or_contains" in result:
                    version = "UNKNOWN"
                    if "version" in result and result["version"] != "UNKNOWN":
                        version = result["version"]
                    elif result["version"] == "UNKNOWN":
                        file_path = "".join(self.file_stack)
                        self.logger.debug(
                            f"{dummy_checker_name} was detected with version UNKNOWN in file {file_path}"
                        )
                    else:
                        self.logger.error(f"No version info for {dummy_checker_name}")

                    if version != "UNKNOWN":
                        file_path = "".join(self.file_stack)
                        self.logger.debug(
                            f'{file_path} {result["is_or_contains"]} {dummy_checker_name} {version}'
                        )
                        for vendor, product in checker.VENDOR_PRODUCT:
                            yield ScanInfo(
                                ProductInfo(vendor, product, version), file_path
                            )

        self.logger.debug(f"Done scanning file: {filename}")

    @staticmethod
    def clean_file_path(filepath: str) -> str:
        """Returns a cleaner filepath by removing temp path from filepath"""

        # we'll recieve a filepath similar to
        # /temp/anything/extractable_filename.extracted/folders/inside/file
        # We'll return /folders/inside/file to be scanned

        # start_point is the point from we want to start trimming
        # len("extracted") = 9
        start_point = filepath.find("extracted") + 9
        return filepath[start_point:]

    def scan_and_or_extract_file(
        self, ectx: TempDirExtractorContext, filepath: str
    ) -> Iterator[ScanInfo]:
        """Runs extraction if possible and desired otherwise scans."""
        # Scan the file
        yield from self.scan_file(filepath)
        # Attempt to extract the file and scan the contents
        if ectx.can_extract(filepath):
            if not self.should_extract:
                LOGGER.warning(
                    f"{filepath} is an archive. Pass -x option to auto-extract"
                )
                return None
            for filename in self.walker([ectx.extract(filepath)]):
                clean_path = self.clean_file_path(filename)
                self.file_stack.append(f" contains {clean_path}")
                yield from self.scan_and_or_extract_file(ectx, filename)
                self.file_stack.pop()

    def recursive_scan(self, scan_path: str) -> Iterator[ScanInfo]:
        with Extractor(logger=self.logger, error_mode=self.error_mode) as ectx:
            if os.path.isdir(scan_path):
                for filepath in self.walker([scan_path]):
                    self.file_stack.append(filepath)
                    yield from self.scan_and_or_extract_file(ectx, filepath)
                    self.file_stack.pop()
            elif os.path.isfile(scan_path):
                self.file_stack.append(scan_path)
                yield from self.scan_and_or_extract_file(ectx, scan_path)
                self.file_stack.pop()
