# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from json import dump, load
from os.path import exists, expanduser, getmtime, join
from time import time
from typing import Dict

import requests

from cve_bin_tool.cve_scanner import CVEData
from cve_bin_tool.log import LOGGER
from cve_bin_tool.output_engine.util import ProductInfo, format_output

JSON_URL = "https://security-tracker.debian.org/tracker/data/json"
DEB_CVE_JSON_PATH = join(
    expanduser("~"), ".cache", "cve-bin-tool", "debian_cve_data.json"
)

UBUNTU_DEBIAN_MAP = {
    "hirsute": "bullseye",
    "groovy": "bullseye",
    "focal": "bullseye",
    "eoan": "buster",
    "disco": "buster",
    "cosmic": "buster",
    "bionic": "buster",
    "artful": "stretch",
    "zesty": "stretch",
    "yakkety": "stretch",
    "xenial": "stretch",
}


class DebianCVETracker:
    def __init__(self, distro_name: str, distro_codename: str, is_backport: bool):
        self.distro_name = distro_name
        self.distro_codename = distro_codename
        self.is_backport = is_backport

    def cve_info(
        self,
        all_cve_data: Dict[ProductInfo, CVEData],
    ):
        """Produces the Backported fixes' info"""

        cve_data = format_output(all_cve_data)
        json_data = self.get_data()
        for cve in cve_data:
            try:
                cve_fix = json_data[cve["product"]][cve["cve_number"]]["releases"][
                    self.compute_distro()
                ]
                if cve_fix["status"] == "resolved":
                    if self.is_backport:
                        if cve_fix["fixed_version"].startswith(cve["version"]):
                            LOGGER.info(
                                f'{cve["product"]}: {cve["cve_number"]} has backported fix in v{cve_fix["fixed_version"]} release.'
                            )
                        else:
                            LOGGER.info(
                                f'{cve["product"]}: No known backported fix for {cve["cve_number"]}.'
                            )
                    else:
                        LOGGER.info(
                            f'{cve["product"]}: {cve["cve_number"]} has available fix in v{cve_fix["fixed_version"]} release.'
                        )
            except KeyError:
                if cve["cve_number"] != "UNKNOWN":
                    LOGGER.info(
                        f'{cve["product"]}: No known fix for {cve["cve_number"]}.'
                    )

    def get_data(self):
        check_json()
        with open(DEB_CVE_JSON_PATH) as jsonfile:
            return load(jsonfile)

    def compute_distro(self):
        if self.distro_name == "ubuntu":
            return UBUNTU_DEBIAN_MAP[self.distro_codename]
        elif self.distro_name == "debian":
            return self.distro_codename


def check_json():
    """Check to update the Debian CVE JSON file"""

    if (
        not exists(DEB_CVE_JSON_PATH)
        or getmtime(DEB_CVE_JSON_PATH) + (24 * 60 * 60) < time()
    ):
        update_json()


def update_json():
    """Update the Debian CVE JSON file"""

    LOGGER.info("Updating Debian CVE JSON file for checking available fixes.")
    response = requests.get(JSON_URL).json()
    with open(DEB_CVE_JSON_PATH, "w") as debian_json:
        dump(response, debian_json, indent=4)
        LOGGER.info("Debian CVE JSON file for checking available fixes is updated.")
