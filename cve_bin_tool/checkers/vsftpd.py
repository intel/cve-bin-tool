# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for vsftpd

https://www.cvedetails.com/product/3475/Beasts-Vsftpd.html?vendor_id=2041
https://www.cvedetails.com/product/62457/Vsftpd-Project-Vsftpd.html?vendor_id=21069

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class VsftpdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"vsFTPd ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("beasts", "vsftpd"), ("vsftpd_project", "vsftpd")]
