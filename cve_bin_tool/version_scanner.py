# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import subprocess
import sys
from re import search

import pkg_resources

from cve_bin_tool.egg_updater import IS_DEVELOP, update_egg
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.extractor import Extractor
from cve_bin_tool.file import is_binary
from cve_bin_tool.log import LOGGER
from cve_bin_tool.package_list_parser.vendor_fetch import VendorFetch
from cve_bin_tool.strings import Strings
from cve_bin_tool.util import DirWalk, ProductInfo, inpath


class InvalidFileError(Exception):
    """Filepath is invalid for scanning."""


class VersionScanner:
    """ "Scans files for CVEs using CVE checkers"""

    CHECKER_ENTRYPOINT = "cve_bin_tool.checker"

    def __init__(
        self,
        should_extract=False,
        exclude_folders=[],
        checkers=None,
        logger=None,
        error_mode=ErrorMode.TruncTrace,
        score=0,
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        # Update egg if installed in development mode
        if IS_DEVELOP():
            self.logger.info("Updating egg_info")
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
        self.file_stack = []
        self.error_mode = error_mode
        # self.logger.info("Checkers loaded: %s" % (", ".join(self.checkers.keys())))

    @classmethod
    def load_checkers(cls):
        """Loads CVE checkers"""
        checkers = dict(
            map(
                lambda checker: (checker.name, checker.load()),
                pkg_resources.iter_entry_points(cls.CHECKER_ENTRYPOINT),
            )
        )
        return checkers

    @classmethod
    def available_checkers(cls):
        checkers = pkg_resources.iter_entry_points(cls.CHECKER_ENTRYPOINT)
        checker_list = [item.name for item in checkers]
        return checker_list

    def remove_skiplist(self, skips):
        # Take out any checkers that are on the skip list
        # (string of comma-delimited checker names)
        skiplist = skips
        for skipme in skiplist:
            if skipme in self.checkers:
                del self.checkers[skipme]
                self.logger.debug(f"Skipping checker: {skipme}")
            else:
                self.logger.error(f"Checker {skipme} is not a valid checker name")

    def print_checkers(self):
        self.logger.info(f'Checkers: {", ".join(self.checkers.keys())}')

    def is_executable(self, filename):
        """check if file is an ELF binary file"""

        if inpath("file"):
            # use system file if available (for performance reasons)
            output = subprocess.check_output(["file", filename])
            output = output.decode(sys.stdout.encoding)

            if "cannot open" in output:
                self.logger.warning(f"Unopenable file {filename} cannot be scanned")
                return False

            if (
                ("LSB " not in output)
                and ("LSB shared" not in output)
                and ("LSB executable" not in output)
                and ("PE32 executable" not in output)
                and ("PE32+ executable" not in output)
                and ("Mach-O" not in output)
                and ("PKG-INFO: " not in output)
                and ("METADATA: " not in output)
            ):
                return False
        # otherwise use python implementation of file
        elif not is_binary(filename):
            return False

        return True, output

    def parse_strings(self, filename):
        """parse binary file's strings"""

        if inpath("strings"):
            # use "strings" on system if available (for performance)
            lines = (
                subprocess.check_output(["strings", filename])
                .decode("utf-8")
                .splitlines()
            )
        else:
            # Otherwise, use python implementation
            s = Strings(filename)
            lines = s.parse()
        return lines

    def scan_file(self, filename):
        """Scans a file to see if it contains any of the target libraries,
        and whether any of those contain CVEs"""

        self.logger.debug(f"Scanning file: {filename}")
        self.total_scanned_files += 1

        # Do not try to scan symlinks
        if os.path.islink(filename):
            return None

        # Ensure filename is a file
        if not os.path.isfile(filename):
            self.logger.warning(f"Invalid file {filename} cannot be scanned")
            return None

        # check if it's an ELF binary file
        try:
            t, output = self.is_executable(filename)
        except:
            t = self.is_executable(filename)

        if not t:
            return None

        # parse binary file's strings
        lines = self.parse_strings(filename)

        #  If python package then strip the lines to avoid detecting other product strings
        if "PKG-INFO: " in output or "METADATA: " in output:
            lines = lines[1:3]
            lines[0] = (
                "--generated pattern for cve-bin-tool " + lines[0] + " " + lines[1]
            )
            yield from self.run_python_package_checkers(filename, lines)

        yield from self.run_checkers(filename, lines)

    def run_python_package_checkers(self, filename, lines):
        """
        This function runs only for python packages.
        There are no actual checkers.
        The ProductInfo is computed without the help of any checkers from PKG-INFO or METADATA.
        """
        product = search(
            r"--generated pattern for cve-bin-tool Name: (.+?) Version:", lines[0]
        ).group(1)
        version = search(r"Version: (.+?)$", lines[1]).group(1)

        with VendorFetch() as vendor_fetch:
            vendor_package_pair = vendor_fetch.get_vendor_product_pairs(product)

        if vendor_package_pair != []:
            vendor = vendor_package_pair[0]["vendor"]
            file_path = "".join(self.file_stack)

            self.logger.info(f"{file_path} is {product} {version}")

            yield ProductInfo(vendor, product, version), file_path

        self.logger.debug(f"Done scanning file: {filename}")

    def run_checkers(self, filename, lines):
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
                        self.logger.warning(
                            f"{dummy_checker_name} was detected with version UNKNOWN in file {file_path}"
                        )
                    else:
                        self.logger.error(f"No version info for {dummy_checker_name}")

                    if version != "UNKNOWN":
                        file_path = "".join(self.file_stack)
                        self.logger.info(
                            f'{file_path} {result["is_or_contains"]} {dummy_checker_name} {version}'
                        )
                        for vendor, product in checker.VENDOR_PRODUCT:
                            yield ProductInfo(vendor, product, version), file_path

        self.logger.debug(f"Done scanning file: {filename}")

    @staticmethod
    def clean_file_path(filepath):
        """Returns a cleaner filepath by removing temp path from filepath"""

        # we'll recieve a filepath similar to
        # /temp/anything/extractable_filename.extracted/folders/inside/file
        # We'll return /folders/inside/file to be scanned

        # start_point is the point from we want to start trimming
        # len("extracted") = 9
        start_point = filepath.find("extracted") + 9
        return filepath[start_point:]

    def scan_and_or_extract_file(self, ectx, filepath):
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

    def recursive_scan(self, scan_path):
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
