# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for Apache commons-compress:

https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-59066/Apache-Commons-Compress.html
"""
from cve_bin_tool.checkers import Checker


class CommonsCompressChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Apache Commons Compress software defines an API for working with",
        r"<url>http://commons.apache.org/proper/commons-compress/</url>",
    ]
    FILENAME_PATTERNS = [r"commons-compress(-[0-9]+\.[0-9]+(\.[0-9]+)?)?.jar"]
    VERSION_PATTERNS = [
        r"<artifactId>commons-compress</artifactId>\r?\n  <version>([0-9]+\.[0-9]+(\.[0-9]+)?)</version>"
    ]
    VENDOR_PRODUCT = [("apache", "commons_compress")]
