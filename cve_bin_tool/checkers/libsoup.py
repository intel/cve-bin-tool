# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for libsoup

https://www.cvedetails.com/product/21096/Gnome-Libsoup.html?vendor_id=283
"""
from cve_bin_tool.checkers import Checker


class LibsoupChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"libsoup"]
    VERSION_PATTERNS = [r"libsoup/([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("gnome", "libsoup"),
        ("joe_shaw", "libsoup"),
        ("libsoup", "libsoup"),
    ]
