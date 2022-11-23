# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for atftp

https://www.cvedetails.com/product/53662/Atftp-Project-Atftp.html?vendor_id=19769

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class AtftpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)\r?\natftp"]
    VENDOR_PRODUCT = [("atftp_project", "atftp")]
