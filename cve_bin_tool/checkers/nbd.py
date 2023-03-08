# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for network_block_device

https://www.cvedetails.com/product/110819/Network-Block-Device-Project-Network-Block-Device.html?vendor_id=26583

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class NbdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"nbd-server version ([0-9]+\.[0-9]+(\.[0-9]+)*)",
        r"\r?\nnbd ([0-9]+\.[0-9]+(\.[0-9]+)*)",
        r"\r?\n([0-9]+\.[0-9]+(\.[0-9]+)*)\r?\nnbd",
    ]
    VENDOR_PRODUCT = [("network_block_device_project", "network_block_device")]
