# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for bird

https://www.cvedetails.com/product/68129/Bird-Project-Bird.html?vendor_id=21737
https://www.cvedetails.com/product/59242/NIC-Bird.html?vendor_id=20536

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class BirdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"BIRD ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("bird_project", "bird"), ("nic", "bird")]
