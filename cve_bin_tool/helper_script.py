# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import argparse
import re
import sys
import textwrap
from collections import ChainMap
from logging import Logger
from pathlib import Path
from typing import MutableMapping

from rich import print as rprint
from rich.console import Console

from cve_bin_tool.cvedb import CVEDB, DBNAME, DISK_LOCATION_DEFAULT
from cve_bin_tool.error_handler import ErrorHandler, ErrorMode, UnknownArchiveType
from cve_bin_tool.extractor import Extractor, TempDirExtractorContext
from cve_bin_tool.log import LOGGER
from cve_bin_tool.strings import parse_strings
from cve_bin_tool.util import DirWalk
from cve_bin_tool.version_scanner import VersionScanner

WARNED = False


class HelperScript:
    """Helps contributors who want to write a new cve-bin-tool checker find common filenames, version strings, and other necessary data for building a binary checker"""

    CONSOLE = Console()
    LOGGER: Logger = LOGGER.getChild("HelperScript")

    def __init__(
        self,
        product_name: str | None = None,
        version_number: str | None = None,
        string_length: int = 40,
    ):
        self.extractor: TempDirExtractorContext = Extractor()
        self.product_name = product_name
        self.version_number = version_number
        self.string_length = string_length

        # for setting the database
        self.connection = None
        self.dbpath = str(Path(DISK_LOCATION_DEFAULT) / DBNAME)

        # for extraction
        self.walker = DirWalk().walk

        # for output (would use in future)
        self.contains_patterns: list[str] = []
        self.filename_pattern: list[str] = []
        self.version_pattern: list[str] = []
        self.vendor_product: list[tuple[str, str]] = []

        self.multiline_pattern: bool = True

        # for scanning files versions
        self.version_scanner = VersionScanner()

    def parse_execfile(self, filename: str) -> list[str] | None:
        """Parses executable file for common patterns, version strings and common filename patterns"""

        LOGGER.debug(f"{filename} <--- this is an ELF binary")
        file_content = parse_strings(filename)

        if self.product_name is None or self.version_number is None:
            return None

        matches = self.search_pattern(
            file_content, self.product_name, self.version_number
        )

        # searching for version strings in the found matches
        version_string = self.search_version_string(matches)
        self.version_pattern += version_string

        # if version string is found in file, append it to filename_pattern
        if version_string:
            if sys.platform == "win32":
                self.filename_pattern.append(filename.split("\\")[-1])
            else:
                self.filename_pattern.append(filename.split("/")[-1])
            LOGGER.info(f"matches for {self.product_name} found in {filename}")

            for i in matches:
                if ("/" not in i and "!" not in i) and len(i) > self.string_length:
                    self.contains_patterns.append(i)

        LOGGER.debug(f"{self.filename_pattern}")
        return matches

    def extract_and_parse_file(self, filename: str) -> list[str] | None:
        """extracts and parses the file for common patterns, version strings and common filename patterns"""

        # if the file is ELF binary file, don't try to parse its filename or extract it
        if self.version_scanner.is_executable(filename)[0]:
            return self.parse_execfile(filename)
        else:
            self.parse_filename(filename)

            with self.extractor as ectx:
                binary_string_list: list[str] = []
                if ectx.can_extract(filename):
                    for filepath in self.walker([ectx.extract(filename)]):
                        clean_path = self.version_scanner.clean_file_path(filepath)
                        LOGGER.debug(f"checking whether {clean_path} is binary")

                        # see if the file is ELF binary file and parse for strings
                        is_exec = self.version_scanner.is_executable(filepath)[0]
                        if is_exec:
                            execfile_path = self.parse_execfile(filepath)
                            if execfile_path is not None:
                                binary_string_list += execfile_path

                if not self.multiline_pattern:
                    self.version_pattern = [
                        x for x in self.version_pattern if "\\n" not in x
                    ]

                # to resolve case when there are no strings common with product_name in them
                if self.contains_patterns:
                    return self.contains_patterns

                return binary_string_list

    def search_pattern(
        self, file_content: str, pattern: str, version_pattern: str
    ) -> list[str]:
        """find strings for CONTAINS_PATTERNS with product_name in them"""

        file_content_list = file_content.split("\n")
        version_pattern = rf".+{version_pattern}"
        matches = []
        product_matches: list[tuple[int, str]] = []
        version_matches: list[tuple[int, str]] = []

        for i, line in enumerate(file_content_list):
            string_present = re.search(pattern, line, re.IGNORECASE)
            version_present = re.search(version_pattern, line, re.IGNORECASE)
            if string_present and version_present:
                if line.find(".debug") != -1:
                    continue
                matches.append(line.strip())
                self.multiline_pattern = False
                continue
            if string_present:
                product_matches.append((i, line.strip()))
            if version_present:
                version_matches.append((i, line.strip()))

        for product_line_number, product in product_matches:
            matches.append(product)

        for version_line_number, version in version_matches:
            if not product_matches:
                break

            closest_product_line_number = min(
                product_matches, key=lambda x: abs(x[0] - version_line_number)
            )[0]
            line_distance = abs(closest_product_line_number - version_line_number)
            closest_products = [
                x
                for x in product_matches
                if abs(x[0] - version_line_number) == line_distance
            ]
            for product_line_number, product in closest_products:
                line = (
                    "(?:(?:\\r?\\n.*?)*)".join([product, version])
                    if version_line_number > product_line_number
                    else "(?:(?:\\r?\\n.*?)*)".join([version, product])
                )
                matches.append(line)

        LOGGER.debug(
            f"found matches = {matches}"
        )  # TODO: regex highlight in these matched strings?
        return matches

    def search_version_string(self, matched_list: list[str]) -> list[str]:
        """finds version strings from matched list"""

        pattern1 = rf"{self.product_name}(.*){self.version_number}"
        pattern2 = rf"{self.version_number}(.*){self.product_name}"
        # ^ this does not work for debian packages

        # pattern3 = rf"{self.product_name}(.*)([0-9]+[.-][0-9]+([.-][0-9]+)?)"
        # this matches patterns like:
        # product1.2.3
        # product 1.2.3
        # product-1.2.3
        # product.1.2.3
        # product version 1.2.3
        # product v1.2.3(1)

        version_strings = [
            i
            for i in matched_list
            if re.search(pattern1, i, re.IGNORECASE | re.DOTALL)
            or re.search(pattern2, i, re.IGNORECASE | re.DOTALL)
            if not i.endswith(
                ".debug"
            )  # removes .debug, so, this does not gets printed
        ]
        LOGGER.debug(
            f"found version-string matches = {version_strings}"
        )  # TODO: regex highlight in these matched strings?
        return version_strings

    def parse_filename(self, filename: str) -> tuple[str, str]:
        """
        returns package_name/product_name from package_filename of types .rpm, .deb, etc.
        Example: package_filename = openssh-client_8.4p1-5ubuntu1_amd64.deb
            here, package_name = openssh-client
        """

        # resolving directory names
        filename = filename.split("\\")[-1].split("/")[-1]

        # if extractable, then parsing for different types of files accordingly
        if self.extractor.can_extract(filename):
            if filename.endswith(".tar.xz"):
                product_name = filename.rsplit("-", 3)[0]
                version_number = filename.rsplit("-", 3)[1]
                # example: libarchive-3.5.1-1-aarch64.pkg.tar.xz
            elif filename.endswith(".deb") or filename.endswith(".ipk"):
                product_name = filename.rsplit("_")[0]
                version_number = filename.rsplit("_")[1].rsplit("-")[0].rsplit("+")[0]
                # example: varnish_6.4.0-3_amd64.deb
            else:
                product_name = filename.rsplit("-", 2)[0]
                version_number = filename.rsplit("-", 2)[1]

            if not self.product_name:
                self.product_name = product_name

            if not self.version_number:
                self.version_number = version_number

            self.vendor_product = self.find_vendor_product()

            LOGGER.debug(
                f"Parsing file '{filename}': Results: product_name='{self.product_name}', version_number='{self.version_number}'"
            )
            return product_name, version_number
        else:
            # raise error for unknown archive types
            with ErrorHandler(mode=ErrorMode.NoTrace, logger=LOGGER):
                raise UnknownArchiveType(filename)

    def find_vendor_product(self) -> list[tuple[str, str]]:
        """find vendor-product pairs from database"""

        LOGGER.debug(
            f"checking for product_name='{self.product_name}' and version_name='{self.version_number}' in the database"
        )

        cursor = CVEDB.db_open_and_get_cursor(self)

        # finding out all distinct (vendor, product) pairs with the help of product_name
        query = """
            SELECT distinct vendor, product FROM cve_range
            WHERE product=(:product);
        """
        if cursor is None:
            return []

        cursor.execute(query, {"product": self.product_name})
        data = cursor.fetchall()
        CVEDB.db_close(self)  # type: ignore

        # checking if (vendor, product) was found in the database
        if data:
            # warning the user to select the vendor-product pairs manually if multiple pairs are found
            global WARNED
            if len(data) != 1 and not WARNED:
                LOGGER.warning(
                    textwrap.dedent(
                        f"""
                            ===============================================================
                            Multiple ("vendor", "product") pairs found for "{self.product_name}"
                            Please manually select the appropriate pair.
                            ===============================================================
                        """
                    )
                )
                WARNED = True  # prevent same warning multiple times
            return data  # [('vendor', 'product')]
        elif self.product_name:
            # removing numeric characters from the product_name
            if any(char.isdigit() for char in self.product_name):
                LOGGER.debug(f"removing digits from product_name={self.product_name}")
                self.product_name = "".join(
                    filter(lambda x: not x.isdigit(), self.product_name)
                )
                return self.find_vendor_product()
            else:
                # raise error and ask for product_name
                LOGGER.warning(
                    textwrap.dedent(
                        f"""
                            =================================================================
                            No match was found for "{self.product_name}" in database.
                            Please check your file or try specifying the "product_name" also.
                            =================================================================
                        """
                    )
                )
        return []

    def output_single(self) -> None:
        """display beautiful output for Helper-Script"""

        if self.product_name is None:
            return

        self.CONSOLE.rule(f"[bold dark_magenta]{self.product_name.capitalize()}Checker")

        rprint(
            textwrap.dedent(
                f"""
                [bright_black]# Copyright (C) 2022 Intel Corporation
                # SPDX-License-Identifier: GPL-3.0-or-later[/]


                [yellow]\"\"\"
                CVE checker for {self.product_name}:

                <provide reference links here>
                \"\"\"[/]
                [magenta]from[/] __future__ [magenta]import[/] annotations

                [magenta]from[/] cve_bin_tool.checkers [magenta]import[/] Checker


                [red]class[/] [blue]{(self.product_name).capitalize()}Checker[/](Checker):"""
            )
        )

        # output: long human readable strings
        print("\tCONTAINS_PATTERNS: list[str] = [")
        for common_strings in sorted(self.contains_patterns):
            if ".debug" in common_strings:
                rprint(
                    f'\t\t[red]r"{escape_rich_console_close(common_strings)}"[/] <--- not recommended to use this form of strings'
                )
                continue  # without this, the else statement was getting printed ;-;
            if ".so" in common_strings:
                rprint(
                    f'\t\t[red]r"{escape_rich_console_close(common_strings)}"[/] <--- not recommended to use this form of strings'
                )
            else:
                rprint(f'\t\t[green]r"{escape_rich_console_close(common_strings)}"[/],')
        print("\t]")

        """
        Using filenames (containing patterns like '.so' etc.) in the binaries as VERSION_PATTERNS aren't ideal.
        The reason behind this is that these might depend on who packages the file (like it
        might work on fedora but not on ubuntu)
        """

        # output: filenames, that we search for binary strings
        print("\tFILENAME_PATTERNS: list[str] = [")
        for filename in self.filename_pattern:
            if self.product_name == filename:
                rprint(
                    f'\t\t[cyan]r"{escape_rich_console_close(filename)}"[/], <--- this is a really common filename pattern'
                )
            elif self.product_name in filename:
                if ".so" in filename:
                    rprint(f'\t\t[green]r"{escape_rich_console_close(filename)}"[/],')
                else:
                    rprint(
                        f'\t\t[bright_green]r"{escape_rich_console_close(filename)}"[/], <--- you could just use "{self.product_name}" to match this file'
                    )  # to single-handedly match filenames of type varnishd, varnishlog, varnishtop, etc.
            else:
                rprint(f'\t\t[green]r"{escape_rich_console_close(filename)}"[/],')
        print("\t]")

        # output: version-strings
        print("\tVERSION_PATTERNS: list[str] = [")
        for version_string in self.version_pattern:
            rprint(f'\t\t[green]r"{escape_rich_console_close(version_string)}"[/],')
        print("\t]")

        # output: vendor-product pair
        print("\tVENDOR_PRODUCT: list[tuple[str, str] = ", end="")
        rprint(self.vendor_product)

        self.CONSOLE.rule()

    @staticmethod
    def output_common(common_strings: list[str], product_name: str) -> None:
        """display beautiful output for common strings in CONTAINS_PATTERNS"""

        HelperScript.CONSOLE.rule(
            f"[bold dark_magenta]Common CONTAINS_PATTERNS strings for {product_name.capitalize()}Checker"
        )
        rprint(f"[red]class[/] [blue]{product_name.capitalize()}Checker[/](Checker):")

        print("\tCONTAINS_PATTERNS = [")
        for common_string in sorted(common_strings):
            if ".debug" in common_string:
                rprint(
                    f'\t\t[red]r"{escape_rich_console_close(common_string)}"[/] <--- not recommended to use this form of strings'
                )
                continue  # without this, the else statement was getting printed ;-;
            if ".so" in common_string:
                rprint(
                    f'\t\t[red]r"{escape_rich_console_close(common_string)}"[/] <--- not recommended to use this form of strings'
                )
            else:
                rprint(f'\t\t[green]r"{escape_rich_console_close(common_string)}"[/],')
        print("\t]")
        HelperScript.CONSOLE.rule()


def escape_rich_console_close(string: str):
    """Escape the closing tag for rich console markup"""
    return string.replace(r"[/]", r"\[/]")


def scan_files(args) -> None:
    """Scans file and outputs Checker class or common CONTAINS_PATTERNS depending on number of files given"""

    LOGGER.debug(f"Given filenames: {args['filenames']}")
    LOGGER.info("Scanning files")

    hs_list: list[HelperScript] = [
        HelperScript(
            product_name=args["product_name"],
            version_number=args["version_number"],
            string_length=args["string_length"],
        )
        for _ in args["filenames"]
    ]

    if len(hs_list) > 1:  # more than one files are given - output common strings
        # return if product_name is not given
        if not args["product_name"]:
            LOGGER.error("PRODUCT_NAME not in arguments")
            return None

        if args["version_number"]:
            LOGGER.warning(
                "VERSION_NUMBER in arguments, common strings may not be found if files have different versions"
            )

        for i, hs in enumerate(hs_list):
            hs.extract_and_parse_file(args["filenames"][i])

        common_strings = hs_list[0].contains_patterns

        # getting common strings
        for hs in hs_list:
            common_strings = list(set(common_strings) & set(hs.contains_patterns))

        if hs_list[0].product_name is not None:
            HelperScript.output_common(common_strings, hs_list[0].product_name)

    else:  # one file is given
        hs_list[0].extract_and_parse_file(args["filenames"][0])
        hs_list[0].output_single()


def main(argv=None) -> None:
    argv = argv or sys.argv

    parser = argparse.ArgumentParser(
        prog="helper-script",
        description=textwrap.dedent(
            """
                Helps contributors who want to write a new cve-bin-tool checker find common filenames,
                version strings, and other necessary data for building a binary checker
                """
        ),
    )
    # scan directory args
    parser.add_argument(
        "filenames",
        help="files to scan",
        nargs="+",
        default=[],
    )

    # product-name args
    parser.add_argument(
        "-p",
        "--product",
        help="provide product-name that would be searched",
        dest="product_name",
        action="store",
        default=None,
    )

    # version-name args
    parser.add_argument(
        "-v",
        "--version",
        help="provide version that would be searched",
        dest="version_number",
        action="store",
        default=None,
    )

    # log level args
    parser.add_argument(
        "-l",
        "--log",
        help="log level (default: warning)",
        dest="log_level",
        action="store",
        choices=["debug", "info", "warning", "error", "critical"],
        default="warning",
    )

    # contains-patterns string length args
    parser.add_argument(
        "--string-length",
        help="changes the output string-length for CONTAINS_PATTERNS (default: %(default)s)",
        type=int,
        action="store",
        default=40,
    )
    with ErrorHandler(mode=ErrorMode.NoTrace):
        raw_args = parser.parse_args(argv[1:])
        args: MutableMapping[str, str] = {
            key: value for key, value in vars(raw_args).items() if value
        }
        defaults = {key: parser.get_default(key) for key in vars(raw_args)}

    args = ChainMap(args, defaults)

    LOGGER.setLevel(args["log_level"].upper())

    scan_files(args)


if __name__ == "__main__":
    main()
