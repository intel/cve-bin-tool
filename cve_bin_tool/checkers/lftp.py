# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for lftp

https://www.cvedetails.com/product/3385/Alexander-V.-Lukyanov-Lftp.html?vendor_id=2010
https://www.cvedetails.com/product/49780/Lftp-Project-Lftp.html?vendor_id=19168

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LftpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["lftp\\/([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [("alexander_v._lukyanov", "lftp"), ("lftp_project", "lftp")]
