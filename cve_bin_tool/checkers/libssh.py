# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libssh

https://www.cvedetails.com/product/23663/Libssh-Libssh.html?vendor_id=12516

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibsshChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"SSH-2.0-libssh_([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libssh", "libssh")]
