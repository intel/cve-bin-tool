# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for exfatprogs

https://www.cvedetails.com/product/163633/Namjaejeon-Exfatprogs.html?vendor_id=33445

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ExfatprogsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nexfatprogs version : %s"]
    VENDOR_PRODUCT = [("namjaejeon", "exfatprogs")]
