# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mosquitto

https://www.cvedetails.com/product/45945/Eclipse-Mosquitto.html?vendor_id=10410

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MosquittoChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"\r?\n([0-9]+\.[0-9]+\.[0-9]+)\r?\nmosquitto"]
    VENDOR_PRODUCT = [("eclipse", "mosquitto")]
