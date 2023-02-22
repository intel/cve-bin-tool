# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for picocom

https://www.cvedetails.com/product/38097/Picocom-Project-Picocom.html?vendor_id=16530

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PicocomChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"picocom v%s\r?\n([0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+)\r?\npicocom v%s",
    ]
    VENDOR_PRODUCT = [("picocom_project", "picocom")]
