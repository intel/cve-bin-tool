# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for domoticz

https://www.cvedetails.com/product/52466/Domoticz-Domoticz.html?vendor_id=19702

Note: domoticz is not provided by debian or openWRT. Tests provided are fedora-only.

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DomoticzChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"domoticz-([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("domoticz", "domoticz")]
