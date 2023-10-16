# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import re
from collections import defaultdict
from logging import Logger
from pathlib import Path
from subprocess import PIPE, run
from typing import Any, Dict, List

import distro

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.error_handler import (
    EmptyTxtError,
    ErrorHandler,
    ErrorMode,
    InvalidListError,
)
from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import ProductInfo, Remarks

ROOT_PATH = Path((__file__), "..").parent.absolute()

DEB_DISTROS = ["debian", "pop", "ubuntu"]
PACMAN_DISTROS = ["arch", "manjaro"]
RPM_DISTROS = ["centos", "fedora", "opensuse", "rhel"]
SUPPORTED_DISTROS = RPM_DISTROS + PACMAN_DISTROS + DEB_DISTROS


class PackageListParser:
    def __init__(
        self,
        input_file: str,
        logger: Logger = LOGGER.getChild("PackageListParser"),
        error_mode=ErrorMode.TruncTrace,
    ) -> None:
        """
        Initialize the PackageListParser object.

        Args:
            input_file (str): The path to the input file containing a list of packages.
            logger (Logger): An optional logger object for logging messages.
            error_mode (ErrorMode): An optional error mode specifying how errors should be handled.
        """
        self.input_file = input_file

        if self.__class__.__name__ != "PackageListParser":
            self.logger = logger.getChild(self.__class__.__name__)
        else:
            self.logger = logger

        self.error_mode = error_mode
        self.parsed_data_without_vendor: Dict[Any, Any] = defaultdict(dict)
        self.parsed_data_with_vendor: Dict[Any, Any] = defaultdict(dict)
        self.package_names_with_vendor: List[Any] = []
        self.package_names_without_vendor: List[Any] = []

    def parse_list(self):
        """
        Parse the package list and return parsed package information.

        Returns:
            Dict[Any, Any]: A dictionary containing parsed package information.
        """
        input_file = self.input_file
        self.check_file()
        installed_packages = []
        if not input_file.endswith("requirements.txt"):
            system_packages = []

            LOGGER.info(f"Scanning {distro.id().capitalize()} package list.")

            if distro.id() in DEB_DISTROS:
                installed_packages = run(
                    [
                        "dpkg-query",
                        "--show",
                        '--showformat={"name": "${binary:Package}", "version": "${Version}"}, ',
                    ],
                    stdout=PIPE,
                )
                installed_packages = json.loads(
                    f"[{installed_packages.stdout.decode('utf-8')[0:-2]}]"
                )
            elif distro.id() in RPM_DISTROS:
                installed_packages = run(
                    [
                        "rpm",
                        "--query",
                        "--all",
                        "--queryformat",
                        '{"name": "%{NAME}", "version": "%{VERSION}"\\}, ',
                    ],
                    stdout=PIPE,
                )
                installed_packages = json.loads(
                    f"[{installed_packages.stdout.decode('utf-8')[0:-2]}]"
                )
            elif distro.id() in PACMAN_DISTROS:
                installed_packages = []

                installed_packages_output = run(
                    ["pacman", "--query"],
                    stdout=PIPE,
                )

                installed_packages_output = installed_packages_output.stdout.decode(
                    "utf-8"
                ).splitlines()

                dict_keys = ["name", "version"]
                for installed_package in installed_packages_output:
                    package_details = installed_package.split(" ")
                    installed_package_dict = dict(zip(dict_keys, package_details))
                    installed_packages.append(installed_package_dict)

            with open(input_file) as req:
                lines = req.readlines()
            for line in lines:
                system_packages.append(re.split("\n", line)[0])

            for installed_package in installed_packages:
                if installed_package["name"] in system_packages:
                    self.package_names_without_vendor.append(installed_package)

        else:
            LOGGER.info("Scanning python package list.")
            txt_package_names = []

            installed_packages_json = run(
                ["pip", "list", "--format", "json"],
                stdout=PIPE,
            )
            installed_packages = json.loads(
                installed_packages_json.stdout.decode("utf-8")
            )

            with open(input_file) as txtfile:
                lines = txtfile.readlines()

                for line in lines:
                    txt_package_names.append(re.split(">|\\[|;|=|\n", line)[0])
                for installed_package in installed_packages:
                    package_name = installed_package["name"].lower()
                    if package_name in txt_package_names:
                        self.package_names_without_vendor.append(installed_package)

        cve_db = CVEDB()
        vendor_package_pairs = cve_db.get_vendor_product_pairs(
            self.package_names_without_vendor
        )

        self.add_vendor(vendor_package_pairs)
        self.parse_data()
        return self.parsed_data_with_vendor

    def add_vendor(self, vendor_package_pairs):
        """
        Add vendor information to package entries based on data retrieved from the CVE database.

        Args:
            vendor_package_pairs: A list of vendor-product pairs obtained from the CVE database.
        """
        for vendor_package_pair in vendor_package_pairs:
            for package_name in self.package_names_without_vendor:
                if vendor_package_pair["product"] == package_name["name"].replace(
                    "*", ""
                ):
                    package_name["vendor"] = vendor_package_pair["vendor"] + "*"
                    self.package_names_with_vendor.append(package_name)
                    self.package_names_without_vendor.remove(package_name)
                    break

    def parse_data(self):
        """
        Parse package data and construct a dictionary with information about each installed package.
        """
        for row in self.package_names_with_vendor:
            product_info = ProductInfo(
                row["vendor"], row["name"].lower(), row["version"]
            )
            self.parsed_data_with_vendor[product_info][
                row.get("cve_number", "").strip() or "default"
            ] = {
                "remarks": Remarks.NewFound,
                "comments": row.get("comments", "").strip(),
                "severity": row.get("severity", "").strip(),
            }
            self.parsed_data_with_vendor[product_info]["paths"] = {""}

    def check_file(self):
        """
        Perform various checks on the input file to ensure its validity and compatibility with the system's package manager.
        """
        input_file = self.input_file
        error_mode = self.error_mode

        if not Path(input_file).is_file:
            with ErrorHandler(mode=error_mode):
                raise FileNotFoundError(input_file)

        if Path(input_file).stat().st_size == 0:
            with ErrorHandler(mode=error_mode):
                raise EmptyTxtError(input_file)

        if not input_file.endswith(".txt"):
            with ErrorHandler(mode=error_mode):
                raise InvalidListError(
                    "Invalid Package list file format (should be .txt)"
                )

        if not input_file.endswith("requirements.txt"):
            if distro.id() not in SUPPORTED_DISTROS:
                LOGGER.warning(
                    f"Package list support only available for {','.join(SUPPORTED_DISTROS)}!"
                )
                with ErrorHandler(mode=error_mode):
                    raise InvalidListError(
                        f"{distro.id().capitalize()} is not supported"
                    )

            elif distro.id() in DEB_DISTROS:
                # Simulate installation on Debian based system using apt-get to check if the file is valid
                output = run(
                    ["xargs", "-a", input_file, "apt-get", "install", "-s"],
                    capture_output=True,
                )

                if output.returncode != 0:
                    invalid_packages = re.findall(
                        r"E: Unable to locate package (.+)",
                        output.stderr.decode("utf-8"),
                    )
                    LOGGER.warning(
                        f"Invalid Package found: {','.join(invalid_packages)}"
                    )
            elif distro.id() in RPM_DISTROS:
                output = run(
                    ["xargs", "-a", input_file, "rpm", "-qi"],
                    capture_output=True,
                )

                not_installed_packages = re.findall(
                    r"package (.+) is not installed", output.stdout.decode("utf-8")
                )
                if not_installed_packages:
                    LOGGER.warning(
                        f"The packages {','.join(not_installed_packages)} seems to be not installed.\nIt is either an invalid package or not installed.\nUse `sudo yum install $(cat package-list)` to install all packages"
                    )
            elif distro.id() in PACMAN_DISTROS:
                output = run(
                    ["xargs", "-a", input_file, "pacman", "-Qk"],
                    capture_output=True,
                )

                not_installed_packages = re.findall(
                    r"error: package '(.+)' was not found",
                    output.stderr.decode("utf-8"),
                )

                if not_installed_packages:
                    LOGGER.warning(
                        f"The packages {','.join(not_installed_packages)} seems to be not installed.\nIt is either an invalid package or not installed.\nUse `sudo pacman -S $(cat package-list)` to install all packages"
                    )
            else:
                # TODO: Replace below error handling with a proper pip install dry run
                # See: https://github.com/pypa/pip/issues/53
                with ErrorHandler(mode=error_mode):
                    raise InvalidListError("Invalid Package list")
