# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for motion

https://www.cvedetails.com/product/88854/Motion-Project-Motion.html?vendor_id=23775

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MotionChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["motion ([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [("motion_project", "motion")]
