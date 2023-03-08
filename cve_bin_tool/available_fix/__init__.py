# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import distro

from cve_bin_tool.cve_scanner import CVEData
from cve_bin_tool.log import LOGGER
from cve_bin_tool.output_engine.util import ProductInfo

from .debian_cve_tracker import UBUNTU_DEBIAN_MAP, DebianCVETracker
from .redhat_cve_tracker import RedhatCVETracker

DEBIAN_DISTROS = ["debian", "ubuntu"]
REDHAT_DISTROS = ["rhel", "centos"]


class AvailableFixReport:
    def __init__(
        self,
        all_cve_data: dict[ProductInfo, CVEData],
        distro_info: str,
        is_backport: bool,
    ):
        self.all_cve_data = all_cve_data
        self.distro_info = distro_info
        self.is_backport = is_backport

    def check_available_fix(self):
        if self.distro_info != "local":
            distro_name, distro_codename = self.distro_info.split("-")
        else:
            distro_name = distro.id()
            distro_codename = distro.codename()

        if distro_name in DEBIAN_DISTROS:
            debian_tracker = DebianCVETracker(
                distro_name, distro_codename, self.is_backport
            )
            debian_tracker.cve_info(self.all_cve_data)
        elif distro_name in REDHAT_DISTROS:
            redhat_tracker = RedhatCVETracker(distro_name, distro_codename)
            redhat_tracker.cve_info(self.all_cve_data)
        elif self.is_backport:
            LOGGER.info(
                f"CVE Binary Tool doesn't support Backported Fix Utility for {distro_name.capitalize()} at the moment."
            )
        else:
            LOGGER.info(
                f"CVE Binary Tool doesn't support Available Fix Utility for {distro_name.capitalize()} at the moment."
            )


def get_backport_supported_distros():
    """Generates a list for --backports-fix option in distro-distro_codename fashion"""

    supported_distros: list[str] = []
    for distro_name in DEBIAN_DISTROS:
        if distro_name == "ubuntu":
            supported_distros += [
                f"{distro_name}-{distro_codename}"
                for distro_codename in UBUNTU_DEBIAN_MAP.keys()
            ]
        else:
            supported_distros += [
                f"{distro_name}-{distro_codename}"
                for distro_codename in set(UBUNTU_DEBIAN_MAP.values())
            ]
    supported_distros.append("local")
    return supported_distros


def get_available_fix_supported_distros():
    """Generates a list for --available-fix option in distro-distro_codename fashion"""

    # Redhat distros have versions from 1 to 9
    supported_distros = [
        f"{distro_name}-{i}" for distro_name in REDHAT_DISTROS for i in range(1, 9)
    ]

    return get_backport_supported_distros() + supported_distros
