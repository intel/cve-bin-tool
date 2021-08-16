# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import os
import re
import sys
import textwrap
from collections import ChainMap

from rich import print as rprint
from rich.console import Console

from cve_bin_tool.cvedb import CVEDB, DBNAME, DISK_LOCATION_DEFAULT
from cve_bin_tool.error_handler import ErrorHandler, ErrorMode, UnknownArchiveType
from cve_bin_tool.extractor import Extractor
from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import DirWalk
from cve_bin_tool.version_scanner import VersionScanner


class HelperScript:
    """Helps contributors who want to write a new cve-bin-tool checker find common filenames, version strings, and other necessary data for building a binary checker"""

    CONSOLE = Console()
    LOGGER = LOGGER.getChild("HelperScript")

    def __init__(
        self, filename, product_name=None, version_number=None, string_length=40
    ):
        self.filename = filename
        self.extractor = Extractor()
        self.product_name, self.version_number = self.parse_filename(filename)
        if product_name:
            self.product_name = product_name
        if version_number:
            self.version_number = version_number
        self.string_length = string_length

        # for setting the database
        self.connection = None
        self.dbpath = os.path.join(DISK_LOCATION_DEFAULT, DBNAME)

        # for extraction
        self.walker = DirWalk().walk

        # for output (would use in future)
        self.contains_patterns = []
        self.filename_pattern = []
        self.version_pattern = []
        self.vendor_product = self.find_vendor_product()

        # for scanning files versions
        self.version_scanner = VersionScanner()

    def extract_and_parse_file(self, filename):
        """extracts and parses the file for common patterns, version strings and common filename patterns"""

        with self.extractor as ectx:
            if ectx.can_extract(filename):
                binary_string_list = []
                for filepath in self.walker([ectx.extract(filename)]):
                    clean_path = self.version_scanner.clean_file_path(filepath)
                    LOGGER.debug(f"checking whether {clean_path} is binary")

                    # see if the file is ELF binary file and parse for strings
                    is_exec = self.version_scanner.is_executable(filepath)[0]
                    if is_exec:
                        LOGGER.debug(f"{clean_path} <--- this is an ELF binary")
                        file_content = self.version_scanner.parse_strings(filepath)

                        matches = self.search_pattern(file_content, self.product_name)

                        # searching for version strings in the found matches
                        version_string = self.search_version_string(matches)
                        self.version_pattern += version_string

                        # if version string is found in file, append it to filename_pattern
                        if version_string:
                            if sys.platform == "win32":
                                self.filename_pattern.append(filepath.split("\\")[-1])
                            else:
                                self.filename_pattern.append(filepath.split("/")[-1])
                            LOGGER.info(
                                f"matches for {self.product_name} found in {clean_path}"
                            )

                            binary_string_list += matches

                            for i in matches:
                                if ("/" not in i and "!" not in i) and len(
                                    i
                                ) > self.string_length:
                                    self.contains_patterns.append(i)

                        LOGGER.debug(f"{self.filename_pattern}")

                # to resolve case when there are no strings common with product_name in them
                if self.contains_patterns:
                    return self.contains_patterns
                return binary_string_list

    def search_pattern(self, file_content, pattern):
        """find strings for CONTAINS_PATTERNS with product_name in them"""

        file_content_list = file_content.split("\n")
        matches = [
            i.strip() for i in file_content_list if re.search(pattern, i, re.IGNORECASE)
        ]
        LOGGER.debug(
            f"found matches = {matches}"
        )  # TODO: regex highlight in these matched strings?
        return matches

    def search_version_string(self, matched_list):
        """finds version strings from matched list"""

        # TODO: add multiline string finding

        pattern1 = rf"{self.product_name}(.*){self.version_number}"
        # ^ this does not work for debian packages

        # pattern2 = rf"{self.product_name}(.*)([0-9]+[.-][0-9]+([.-][0-9]+)?)"
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
            if re.search(pattern1, i, re.IGNORECASE)
            if not i.endswith(
                ".debug"
            )  # removes .debug, so, this does not gets printed
        ]
        LOGGER.debug(
            f"found version-string matches = {version_strings}"
        )  # TODO: regex highlight in these matched strings?
        return version_strings

    def parse_filename(self, filename):
        """
        returns package_name/product_name from package_filename of types .rpm, .deb, etc.
        Example: package_filename = openssh-client_8.4p1-5ubuntu1_amd64.deb
            here, package_name = openssh-client
        """

        # resolving directory names
        if sys.platform == "win32":
            filename = filename.split("\\")[-1]
        else:
            filename = filename.split("/")[-1]

        # if extractable, then parsing for different types of files accordingly
        if self.extractor.can_extract(filename):
            if filename.endswith(".tar.xz"):
                product_name = filename.rsplit("-", 3)[0]
                version_number = filename.rsplit("-", 3)[1]
                # example: libarchive-3.5.1-1-aarch64.pkg.tar.xz
            elif filename.endswith(".deb") or filename.endswith(".ipk"):
                product_name = filename.rsplit("_")[0]
                version_number = filename.rsplit("_")[1]
                # example: varnish_6.4.0-3_amd64.deb
            else:
                product_name = filename.rsplit("-", 2)[0]
                version_number = filename.rsplit("-", 2)[1]

            LOGGER.debug(
                f"Parsing file '{self.filename}': Results: product_name='{product_name}', version_number='{version_number}'"
            )
            return product_name, version_number
        else:
            # raise error for unknown archive types
            with ErrorHandler(mode=ErrorMode.NoTrace, logger=LOGGER):
                raise UnknownArchiveType(filename)

    def find_vendor_product(self):
        """find vendor-product pairs from database"""

        LOGGER.debug(
            f"checking for product_name='{self.product_name}' and version_name='{self.version_number}' in the database"
        )

        CVEDB.db_open(self)
        cursor = self.connection.cursor()

        # finding out all distinct (vendor, product) pairs with the help of product_name
        query = """
            SELECT distinct vendor, product FROM cve_range
            WHERE product=(:product);
        """

        cursor.execute(query, {"product": self.product_name})
        data = cursor.fetchall()

        # checking if (vendor, product) was found in the database
        if data:
            # warning the user to select the vendor-product pairs manually if multiple pairs are found
            if len(data) != 1:
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
            return data  # [('vendor', 'product')]
        else:
            if self.product_name:
                # removing numeric characters from the product_name
                if any(char.isdigit() for char in self.product_name):
                    LOGGER.debug(
                        f"removing digits from product_name={self.product_name}"
                    )
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

        CVEDB.db_close(self)

    def output(self):
        """display beautiful output for Helper-Script"""

        self.CONSOLE.rule(f"[bold dark_magenta]{self.product_name.capitalize()}Checker")

        rprint(
            textwrap.dedent(
                f"""
                [bright_black]# Copyright (C) 2021 Intel Corporation
                # SPDX-License-Identifier: GPL-3.0-or-later[/]


                [yellow]\"\"\"
                CVE checker for {self.product_name}:

                <provide reference links here>
                \"\"\"[/]
                [magenta]from[/] cve_bin_tool.checkers [magenta]import[/] Checker


                [red]class[/] [blue]{(self.product_name).capitalize()}Checker[/](Checker):"""
            )
        )

        # output: long human readable strings
        print("\tCONTAINS_PATTERNS = [")
        for common_strings in sorted(self.contains_patterns):
            if ".debug" in common_strings:
                rprint(
                    f'\t\t[red]r"{common_strings}"[/] <--- not recommended to use this form of strings'
                )
                continue  # without this, the else statement was getting printed ;-;
            if ".so" in common_strings:
                rprint(
                    f'\t\t[red]r"{common_strings}"[/] <--- not recommended to use this form of strings'
                )
            else:
                rprint(f'\t\t[green]r"{common_strings}"[/],')
        print("\t]")

        """
        Using filenames (containing patterns like '.so' etc.) in the binaries as VERSION_PATTERNS aren't ideal.
        The reason behind this is that these might depend on who packages the file (like it
        might work on fedora but not on ubuntu)
        """

        # output: filenames, that we search for binary strings
        print("\tFILENAME_PATTERNS = [")
        for filename in self.filename_pattern:
            if self.product_name == filename:
                rprint(
                    f'\t\t[cyan]r"{filename}"[/], <--- this is a really common filename pattern'
                )
            elif self.product_name in filename:
                if ".so" in filename:
                    rprint(f'\t\t[green]r"{filename}"[/],')
                else:
                    rprint(
                        f'\t\t[bright_green]r"{filename}"[/], <--- you could just use "{self.product_name}" to match this file'
                    )  # to single-handedly match filenames of type varnishd, varnishlog, varnishtop, etc.
            else:
                rprint(f'\t\t[green]r"{filename}"[/],')
        print("\t]")

        # output: version-strings
        print("\tVERSION_PATTERNS = [")
        for version_string in self.version_pattern:
            rprint(f'\t\t[green]r"{version_string}"[/],')
        print("\t]")

        # output: vendor-product pair
        print("\tVENDOR_PRODUCT = ", end="")
        rprint(self.vendor_product)

        self.CONSOLE.rule()


def main(argv=None):

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
    )

    # product-name args
    parser.add_argument(
        "-p",
        "--product",
        help="provide product-name that would be searched",
        dest="product_name",
        action="store",
    )

    # version-name args
    parser.add_argument(
        "-v",
        "--version",
        help="provide version that would be searched",
        dest="version_number",
        action="store",
    )

    # log level args
    parser.add_argument(
        "-l",
        "--log",
        help="log level (default: warning)",
        dest="log_level",
        action="store",
        choices=["debug", "info", "warning", "error", "critical"],
    )

    # contains-patterns string length args
    parser.add_argument(
        "--string-length",
        help="changes the output string-length for CONTAINS_PATTERNS (default: %(default)s)",
        type=int,
        action="store",
        default=40,
    )

    defaults = {
        "filenames": [],
        "product_name": None,
        "version_number": None,
        "log_level": "warning",
        "string_length": 40,
    }

    with ErrorHandler(mode=ErrorMode.NoTrace):
        raw_args = parser.parse_args(argv[1:])
        args = {key: value for key, value in vars(raw_args).items() if value}

    args = ChainMap(args, defaults)

    LOGGER.setLevel(args["log_level"].upper())

    LOGGER.debug(f"Given filenames: {args['filenames']}")
    LOGGER.info(f"Scanning only the first filename: '{args['filenames'][0]}'")
    hs = HelperScript(
        args["filenames"][0],
        product_name=args["product_name"],
        version_number=args["version_number"],
        string_length=args["string_length"],
    )

    # Parsing, Extracting and Searching for version-strings
    hs.extract_and_parse_file(args["filenames"][0])

    # output on console
    hs.output()


if __name__ == "__main__":
    main()
