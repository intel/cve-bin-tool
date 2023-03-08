# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for sofia-sip

https://www.cvedetails.com/product/116029/Signalwire-Sofia-sip.html?vendor_id=25697

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SofiaSipChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"sofia-sip-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("signalwire", "sofia-sip")]
