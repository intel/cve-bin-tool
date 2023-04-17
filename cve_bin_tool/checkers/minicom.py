# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for minicom

https://www.cvedetails.com/product/909/Minicom-Minicom.html?vendor_id=525
https://www.cvedetails.com/product/66964/Minicom-Project-Minicom.html?vendor_id=21636

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MinicomChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["Minicom([0-9]+\\.[0-9]+(\\.[0-9]+)*)"]
    VENDOR_PRODUCT = [("minicom", "minicom"), ("minicom_project", "minicom")]
