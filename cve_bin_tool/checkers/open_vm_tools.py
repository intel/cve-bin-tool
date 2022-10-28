# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for open-vm-tools
https://www.cvedetails.com/product/20666/?q=Open-vm-tools
"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpenVmToolsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"libvmtools.so"]
    VERSION_PATTERNS = [
        r"open-vm-tools-([0-9]+\.[0-9]+\.[0-9]+)",
        r"open-vm-tools-stable-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("vmware", "open-vm-tools")]
