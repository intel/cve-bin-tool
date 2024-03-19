# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from re import search, split

from cve_bin_tool.cve_scanner import CVEData
from cve_bin_tool.log import LOGGER
from cve_bin_tool.output_engine.util import ProductInfo, format_output
from cve_bin_tool.util import make_http_requests

RH_CVE_API = "https://access.redhat.com/hydra/rest/securitydata/cve"


class RedhatCVETracker:
    def __init__(self, distro_name: str, distro_codename: str):
        self.distro_name = distro_name
        self.distro_codename = distro_codename

    def cve_info(
        self,
        all_cve_data: dict[ProductInfo, CVEData],
    ):
        """Produces the available fixes' info"""

        cve_data = format_output(all_cve_data, None)
        for cve in cve_data:
            if cve["cve_number"] != "UNKNOWN":
                json_data = self.get_data(cve["cve_number"], cve["product"])
                try:
                    if not json_data:
                        raise KeyError

                    package_state = json_data["package_state"]
                    affected_releases = json_data["affected_release"]

                    no_fix = True

                    for package in affected_releases:
                        if (
                            package["product_name"]
                            == f"Red Hat Enterprise Linux {self.distro_codename}"
                        ):
                            package_data = self.parse_package_data(package["package"])
                            LOGGER.info(
                                f'{cve["product"]}: {cve["cve_number"]} - Status: Fixed - Fixed package: {package_data}'
                            )
                            no_fix = False

                    for package in package_state:
                        if (
                            package["product_name"]
                            == f"Red Hat Enterprise Linux {self.distro_codename}"
                        ):
                            package_data = self.parse_package_data(
                                package["package_name"]
                            )
                            LOGGER.info(
                                f'{cve["product"]}: {cve["cve_number"]} - Status: {package["fix_state"]} - Related package: {package_data}'
                            )
                            no_fix = False

                    if no_fix:
                        LOGGER.info(
                            f'{cve["product"]}: No known fix for {cve["cve_number"]}.'
                        )

                except (KeyError, TypeError):
                    if cve["cve_number"] != "UNKNOWN":
                        LOGGER.info(
                            f'{cve["product"]}: No known fix for {cve["cve_number"]}.'
                        )

    def get_data(self, cve_number: str, product: str):
        """
        Retrieves data for a specific CVE number.
        """
        full_query = f"{RH_CVE_API}/{cve_number}.json"
        return make_http_requests("json", url=full_query, timeout=300)

    def parse_package_data(self, package_data: str) -> str:
        """
        Parses package name and version data from the package data provided by Red Hat.

        Sample input:
        nodejs:12-8040020210817133458.522a0ee4
        edk2-0:20210527gite1999b264f1f-3.el8
        dnsmasq-0:2.79-13.el8_3.1

        Sample output:
        nodejs v12
        edk v2
        dnsmasq v2.79

        """
        parsed_package_data = ""
        package_name = split(r"-\d", package_data, 1)[0]
        if ":" in package_name:
            package_name, package_version = split(":", package_name)
            package_version = search(r"\d+", package_version)
            if package_version:
                package_version = package_version.group(0)
            parsed_package_data = f"{package_name} v{package_version}"
        else:
            parsed_package_data = package_name
            match = search(r"\d+\.\d+", package_data)
            if match:
                package_version = match.group(0)
                parsed_package_data += f" v{package_version}"

        return parsed_package_data
