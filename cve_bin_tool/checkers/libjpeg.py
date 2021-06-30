# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

# pylint: disable=invalid-name

"""
CVE checker for libjpg-turbo

Note that this file is named libjpeg.py instead of libjpeg-turbo.py to avoid an issue
with loading the checker.

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-17075/product_id-40849/Libjpeg-turbo-Libjpeg-turbo.html
"""
from cve_bin_tool.checkers import Checker


class LibjpegChecker(Checker):
    CONTAINS_PATTERNS = [
        r"LIBJPEG",
        r"Caution: quantization tables are too coarse for baseline JPEG",
        r"Invalid JPEG file structure: two SOF markers",
    ]
    FILENAME_PATTERNS = [r"libjpg.so."]
    VERSION_PATTERNS = [
        r"libjpeg-turbo version ([0-9]\.[0-9]\.[0-9])",
        r"LIBJPEGTURBO_([0-9]+\.[0-9]+\.?[0-9]?)",
        r"LIBJPEG_([0-9]+\.[0-9]+\.?[0-9]?)",
    ]
    VENDOR_PRODUCT = [("libjpeg-turbo", "libjpeg-turbo")]
