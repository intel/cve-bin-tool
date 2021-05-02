# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libxslt
https://www.cvedetails.com/product/14676/Xmlsoft-Libxslt.html?vendor_id=1962
"""
from cve_bin_tool.checkers import Checker


class LibxsltChecker(Checker):
    CONTAINS_PATTERNS = [
        r"libxslt.so.1",
        r"xsltLibxsltVersion",
        r"Using libxml %s, libxslt %s and libexslt %s",
        r"xsltproc was compiled against libxml %d, libxslt %d and libexslt %d",
        r"libxslt %d was compiled against libxml %d",
    ]
    FILENAME_PATTERNS = [r"xsltproc"]
    VERSION_PATTERNS = [r"libxslt\.so\.([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("xmlsoft", "libxslt")]
