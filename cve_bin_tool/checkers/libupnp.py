# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libupnp:

https://www.cvedetails.com/product/32362/Libupnp-Project-Libupnp.html?vendor_id=15599
https://www.cvedetails.com/product/82073/Pupnp-Project-Pupnp.html?vendor_id=23052

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibupnpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"Portable SDK for UPnP devices/([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("libupnp_project", "libupnp"), ("pupnp_project", "pupnp")]
