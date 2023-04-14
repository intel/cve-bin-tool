# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import subprocess
import sys
from logging import Logger
from pathlib import Path, PurePath
from typing import Iterator

from cve_bin_tool.checkers import Checker
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.egg_updater import IS_DEVELOP, update_egg
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.extractor import Extractor, TempDirExtractorContext
from cve_bin_tool.file import is_binary
from cve_bin_tool.log import LOGGER
from cve_bin_tool.parsers.parse import parse, valid_files
from cve_bin_tool.strings import parse_strings
from cve_bin_tool.util import DirWalk, ProductInfo, ScanInfo, inpath

if sys.version_info >= (3, 10):
    from importlib import metadata as importlib_metadata
else:
    import importlib_metadata
if sys.version_info >= (3, 9):
    import importlib.resources as resources
else:
    import importlib_resources as resources


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
        self.language_checkers = self.available_language_checkers()

    @classmethod
    def load_checkers(cls) -> dict[str, type[Checker]]:
        """Loads CVE checkers"""
        checkers = dict(
            map(
                lambda checker: (checker.name, checker.load()),
                importlib_metadata.entry_points().select(group=cls.CHECKER_ENTRYPOINT),
            )
        )
        return checkers

    @classmethod
    def available_checkers(cls) -> list[str]:
        checkers = importlib_metadata.entry_points().select(
            group=cls.CHECKER_ENTRYPOINT
        )
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

    # Language Checkers
    LANGUAGE_CHECKER_ENTRYPOINT = "cve_bin_tool.parsers"

    @classmethod
    def available_language_checkers(cls) -> list[str]:
        """Find Language checkers"""
        language_directory = resources.files(cls.LANGUAGE_CHECKER_ENTRYPOINT)
        parsers = language_directory.iterdir()
        language_checkers = []
        for parser in parsers:
            if str(parser).endswith(".py"):
                language = PurePath(parser).name.replace(".py", "").capitalize()
                if language not in ["__init__", "Parse"]:
                    language_checkers.append(language)

        return sorted(language_checkers)

    def print_language_checkers(self) -> None:
        self.logger.info(f'Language Checkers: {", ".join(self.language_checkers)}')

    def number_of_language_checkers(self) -> int:
        return len(self.language_checkers)

    def is_executable(self, filename: str) -> tuple[bool, str | None]:
        """check if file is an ELF binary file"""

        output: str | None = None
        if inpath("file"):
            # use system file if available (for performance reasons)
            try:
                output = subprocess.check_output(["file", filename]).decode(
                    sys.stdout.encoding
                )
            except Exception as e:
                output = "cannot open"
                self.logger.warning(f"Unable to open {filename}: {repr(e)}")

            if "cannot open" in output:
                self.logger.warning(f"Unopenable file {filename} cannot be scanned")
                return False, None

            # Valid binary formats + special files
            if all(
                format not in output
                for format in (
                    "LSB",
                    "MSB",
                    "PE32 executable",
                    "PE32+ executable",
                    "Mach-O",
                    ": data",
                    *list(valid_files.keys()),
                )
            ):
                return False, None
        # otherwise use python implementation of file
        elif not is_binary(filename):
            return False, None

        return True, output

    def is_linux_kernel(self, filename: str) -> tuple[bool, str | None]:
        """check if file is a Linux kernel image"""

        output: str | None = None
        if inpath("file"):
            try:
                output = subprocess.check_output(["file", filename]).decode(
                    sys.stdout.encoding
                )
            except Exception as e:
                output = "cannot open"
                self.logger.warning(f"Unable to open {filename}: {repr(e)}")

            if "cannot open" in output:
                self.logger.warning(f"Unopenable file {filename} cannot be scanned")
                return False, None

            if "Linux" in output:
                return True, None

        return False, output

    def scan_file(self, filename: str) -> Iterator[ScanInfo]:
        """Scans a file to see if it contains any of the target libraries,
        and whether any of those contain CVEs"""

        self.logger.debug(f"Scanning file: {filename}")
        self.total_scanned_files += 1

        # Do not try to scan symlinks
        if Path(filename).is_symlink():
            return None

        # Ensure filename is a file
        if not Path(filename).is_file():
            self.logger.debug(f"Invalid file {filename} cannot be scanned")
            return None

        # check if it's an ELF binary file
        is_exec, output = self.is_executable(filename)

        # check if it's a Linux kernel image
        is_linux_kernel, output = self.is_linux_kernel(filename)

        if not is_exec and not is_linux_kernel:
            return None

        # parse binary file's strings
        lines = parse_strings(filename)

        if output:
            valid_file = False
            for file in list(valid_files.keys()):
                valid_file = valid_file | (file in output)
            if valid_file:
                yield from parse(filename, output, self.cve_db, self.logger)

        yield from self.run_checkers(filename, lines)

    def run_checkers(self, filename: str, lines: str) -> Iterator[ScanInfo]:
        # tko
        for dummy_checker_name, checker in self.checkers.items():
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
            if Path(scan_path).is_dir():
                for filepath in self.walker([scan_path]):
                    self.file_stack.append(filepath)
                    yield from self.scan_and_or_extract_file(ectx, filepath)
                    self.file_stack.pop()
            elif Path(scan_path).is_file():
                self.file_stack.append(scan_path)
                yield from self.scan_and_or_extract_file(ectx, scan_path)
                self.file_stack.pop()
