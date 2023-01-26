# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for libsolv

https://www.cvedetails.com/vulnerability-list/vendor_id-8184/product_id-51703/Opensuse-Libsolv.html

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibsolvChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"libsolv.so", r"libsolvext.so"]
    VERSION_PATTERNS = [
        r"libsolv(?:\.so\.1)?-([0-9]+\.[0-9]+\.[0-9]+)",
        r"libsolv/([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("opensuse", "libsolv")]
