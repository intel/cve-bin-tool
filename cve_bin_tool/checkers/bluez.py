# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for bluez

https://www.cvedetails.com/product/35116/Bluez-Bluez.html?vendor_id=8316
https://www.cvedetails.com/product/35329/Bluez-Project-Bluez.html?vendor_id=3242

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class BluezChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"bluez-([0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+)\r?\n[a-zA-Z :]*(?:BlueZ|hcidump|hcitool|OBEX daemon)",
    ]
    VENDOR_PRODUCT = [("bluez", "bluez"), ("bluez_project", "bluez")]
