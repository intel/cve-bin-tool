# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import re
import subprocess
import sys
import textwrap

from rich import print as rprint
from rich.console import Console

from cve_bin_tool.cvedb import CVEDB, DBNAME, DISK_LOCATION_DEFAULT
from cve_bin_tool.error_handler import (
    ErrorHandler,
    ErrorMode,
    InsufficientArgs,
    UnknownArchiveType,
)
from cve_bin_tool.extractor import Extractor
from cve_bin_tool.file import is_binary
from cve_bin_tool.log import LOGGER
from cve_bin_tool.strings import Strings
from cve_bin_tool.util import DirWalk, inpath
from cve_bin_tool.version_scanner import (  # using it just for clean_file_path
    VersionScanner,
)


class HelperScript:
    """Helps contributors who want to write a new cve-bin-tool checker find common filenames, version strings, and other necessary data for building a binary checker"""

    CONSOLE = Console()

    def __init__(self, filename, product_name=None):
        self.filename = filename
        self.extractor = Extractor()
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.product, self.version = self.parse_filename(filename)
        if product_name:
            self.product = product_name

        # for setting the database
        self.connection = None
        self.dbpath = os.path.join(DISK_LOCATION_DEFAULT, DBNAME)

        # for extraction
        self.walker = DirWalk().walk
        self.file_stack = []  # stores extracted filepaths

        # for output (would use in future)
        self.contain_patterns = []
        self.filename_pattern = []
        self.version_pattern = []
        self.vendor_product = self.find_vendor_product()

    def extract_and_parse_file(self, filename):
        """extracts and parses the file for common patterns, version strings and common filename patterns"""

        with self.extractor as ectx:
            if ectx.can_extract(filename):
                binary_string_list = []
                for filepath in self.walker([ectx.extract(filename)]):
                    clean_path = VersionScanner.clean_file_path(filepath)
                    self.file_stack.append(f"{clean_path}")
                    # self.logger.warning(f"scanning binaries from {clean_path}")

                    # see if the file is ELF binary file and parse for strings
                    if self.is_executable(filepath):
                        # self.logger.warning(f"{clean_path} <--- this is an ELF binary")
                        string_list = [i.strip() for i in self.parse_strings(filepath)]
                        matches = self.search_pattern(string_list)

                        # searching for version strings in the found matches
                        version_string = self.search_version_string(matches)
                        self.version_pattern += version_string

                        # if version string is found in file, append it to filename_pattern
                        if version_string:
                            if sys.platform == "win32":
                                self.filename_pattern.append(filepath.split("\\")[-1])
                            else:
                                self.filename_pattern.append(filepath.split("/")[-1])
                            binary_string_list += matches

                            for i in matches:
                                if ("/" not in i and "!" not in i) and len(i) > 40:
                                    self.contain_patterns.append(i)

                        # self.logger.debug(f"{self.filename_pattern}")

                # to resolve case when there are no strings common with product_name in them
                if self.contain_patterns:
                    return self.contain_patterns
                else:
                    return binary_string_list

    def is_executable(self, filename):
        """checks if given file is executable/ELF binary file"""

        if inpath("file"):
            # using system file if available (for performance reasons)
            o = subprocess.check_output(["file", filename])
            o = o.decode(sys.stdout.encoding)

            if (
                ("LSB " not in o)
                and ("LSB shared" not in o)
                and ("LSB executable" not in o)
                and ("PE32 executable" not in o)
                and ("PE32+ executable" not in o)
                and ("Mach-O" not in o)
            ):
                return False
        # else using python implementation of file
        elif not is_binary(filename):
            return False

        return True

    def parse_strings(self, filename):
        """parse binary file's strings"""

        # self.logger.debug(f"running for strings over {filepath}")
        if inpath("strings"):
            # use "strings" on system if available (for performance)
            o = subprocess.check_output(["strings", filename])
            lines = o.decode("utf-8").splitlines()
        else:
            # Otherwise, use python implementation
            s = Strings(filename)
            lines = s.parse()
        return lines

    def search_pattern(self, string_list):
        """find strings for CONTAIN_PATTERNS with product_name in them"""

        pattern = rf"{self.product}"
        matched = [
            i.strip() for i in string_list if re.search(pattern, i, re.IGNORECASE)
        ]
        return matched

    def search_version_string(self, matched_list):
        """finds version strings from matched list"""

        # pattern = rf"{self.product}(.*){self.version}"
        # ^ this does not work for debian packages
        pattern = rf"{self.product}(.*)([0-9]+[.-][0-9]+([.-][0-9]+)?)"
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
            if re.search(pattern, i, re.IGNORECASE)
            if not i.endswith(
                ".debug"
            )  # removes .debug, so, this does not gets printed
        ]
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

            self.logger.debug(
                f"The product and version are '{product_name}', '{version_number}'"
            )
            return product_name, version_number
        else:
            ### raise error for unknown archive types
            with ErrorHandler(mode=ErrorMode.NoTrace, logger=self.logger):
                raise UnknownArchiveType(filename)

    def find_vendor_product(self):
        """find vendor-product pairs from database"""

        # self.logger.debug(f"product_name='{self.product}'")

        CVEDB.db_open(self)
        cursor = self.connection.cursor()

        # finding out all distinct (vendor, product) pairs with the help of product_name
        query = f"""
            SELECT distinct vendor, product FROM cve_range
            WHERE product=(:product);
        """

        cursor.execute(query, {"product": self.product})
        data = cursor.fetchall()

        # checking if (vendor, product) was found in the database
        if data:
            # warning the user to select the vendor-product pairs manually if multiple pairs are found
            if len(data) != 1:
                self.logger.warning(
                    textwrap.dedent(
                        f"""
                            ============================================
                            Multiple ("vendor", "product") pairs found.
                            Please manually select the appropriate pair.
                            ============================================
                        """
                    )
                )
            return data  # [('vendor', 'product')]
        else:
            if self.product:
                # removing numeric characters from the product_name
                if any(char.isdigit() for char in self.product):
                    # self.logger.debug(f"removing digits from product_name.")
                    self.product = "".join(
                        filter(lambda x: not x.isdigit(), self.product)
                    )
                    return self.find_vendor_product()
                else:
                    ### raise error and ask for product_name
                    self.logger.warning(
                        textwrap.dedent(
                            f"""
                                =================================================================
                                No match was found for "{self.product}" in database. 
                                Please check your file or try specifying the "product_name" also.
                                =================================================================
                            """
                        )
                    )
                    return []

        CVEDB.db_close(self)

    def output(self):
        """display beautiful output for Helper-Script"""

        self.CONSOLE.rule(f"[bold dark_magenta]{self.product.capitalize()}Checker")

        # output: long human readable strings
        print("CONTAIN_PATTERNS = [")
        for common_strings in sorted(self.contain_patterns):
            if ".debug" in common_strings:
                rprint(
                    f'\t[red]r"{common_strings}"[/] <--- not recommended to use these form of strings'
                )
                continue  # without this, the else statement was getting printed ;-;
            if ".so" in common_strings:
                rprint(
                    f'\t[red]r"{common_strings}"[/] <--- not recommended to use these form of strings'
                )
            else:
                rprint(f'\t[green]r"{common_strings}"[/],')
        print("]")

        """
        Using filenames (containing patterns like '.so' etc.) in the binaries as VERSION_PATTERNS aren't ideal.
        The reason behind this is that these might depend on who packages the file (like it 
        might work on fedora but not on ubuntu)
        """

        # output: filenames, that we search for binary strings
        print("FILENAME_PATTERNS = [")
        for filename in self.filename_pattern:
            if self.product == filename:
                rprint(
                    f'\t[cyan]r"{filename}"[/], <--- this is a really common filename pattern'
                )
            elif self.product in filename:
                if ".so" in filename:
                    rprint(f'\t[green]r"{filename}"[/],')
                else:
                    rprint(
                        f'\t[bright_green]r"{filename}"[/], <--- you could just use "{self.product}" to match this file'
                    )  # to single-handedly match filenames of type varnishd, varnishlog, varnishtop, etc.
            else:
                rprint(f'\t[green]r"{filename}"[/],')
        print("]")

        # output: version-strings
        print("VERSION_PATTERNS = [")
        for version_string in self.version_pattern:
            rprint(f'\t[green]r"{version_string}"[/],')
        print("]")

        # output: vendor-product pair
        print("VENDOR_PRODUCT = ", end="")
        rprint(self.vendor_product)

        self.CONSOLE.rule()


def main(filenames, product_name=None):
    # finds common strings across multiple files for CONTAIN_PATTERNS
    hs = HelperScript(filenames[1], product_name=product_name)
    binary_string_list_1 = hs.extract_and_parse_file(filenames[1])
    binary_string_list_2 = []

    for filename in filenames[2:]:
        hs = HelperScript(filename)
        binary_string_list_2 = hs.extract_and_parse_file(filename)

        if binary_string_list_2:
            binary_string_list_1 = list(
                set(binary_string_list_1).intersection(set(binary_string_list_2))
            )

            hs.contain_patterns = binary_string_list_1
            binary_string_list_2 = []

    hs.output()


if __name__ == "__main__":
    # accepting arguments
    args = sys.argv

    ### raise error if no file given
    if len(args) == 1:
        with ErrorHandler(mode=ErrorMode.NoTrace, logger=LOGGER):
            raise InsufficientArgs("Atleast 1 input file is required")

    # when product_name is given as last argument
    # product_name must only contain alphabets
    if args[-1].isalpha() and len(args) == 3:
        filenames, product_name = args[:-1], args[-1]
        main(filenames, product_name)
    else:
        filenames = args[:]
        main(filenames)
