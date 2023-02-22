# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for open-iscsi

https://www.cvedetails.com/product/42438/Open-iscsi-Project-Open-iscsi.html?vendor_id=17429

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpenIscsiChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"# BEGIN RECORD ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("open-iscsi_project", "open-iscsi")]
