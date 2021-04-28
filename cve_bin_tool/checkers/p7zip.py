# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for P7zip
--------
References:
https://www.cvedetails.com/vulnerability-list/vendor_id-9220/product_id-30936/version_id-204168/7-zip-P7zip-16.02.html
"""
from cve_bin_tool.checkers import Checker


class P7ZipChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Copyright (c) 1999-2020 Igor Pavlov",
    ]
    FILENAME_PATTERNS = [r"7za", r"7z"]
    VERSION_PATTERNS = [r"7-Zip.*? ([0-9]{2}\.[0-9]{2}) : Copyright"]
    VENDOR_PRODUCT = [("7-zip", "p7zip")]
