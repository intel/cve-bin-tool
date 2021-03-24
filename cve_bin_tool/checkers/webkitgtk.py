# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for WebKitGTK

https://www.cvedetails.com/product/20596/Webkitgtk-Webkitgtk.html?vendor_id=11350
"""

from . import Checker


class WebkitgtkChecker(Checker):
    CONTAINS_PATTERNS = [r"www.webkitgtk.org"]
    FILENAME_PATTERNS = [
        r"libwebkitgtk",
        r"WebKitGTK-([0-9]+\.[0-9]+).mo",
    ]
    VERSION_PATTERNS = [
        r"webkitgtk-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("webkitgtk", "webkitgtk")]
