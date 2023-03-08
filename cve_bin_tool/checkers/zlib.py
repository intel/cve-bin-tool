# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for zlib
--------
References:
http://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-1820/GNU-Zlib.html
https://www.cvedetails.com/vulnerability-list/vendor_id-13265/product_id-111843/Zlib-Zlib.html
https://zlib.net/ChangeLog.txt

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=72&product_id=1820&version_id=&orderby=2&cvssscoremin=0
"""
from string import printable

from cve_bin_tool.checkers import Checker


class ZlibChecker(Checker):
    CONTAINS_PATTERNS = [
        rf"deflate[{printable}]*Copyright 1995-2005 Jean-loup Gailly",
        rf"Copyright 1995-2005 Mark Adler[{printable}]*inflate",
        r"Copyright 1995-2017 Jean-loup Gailly and Mark Adler",
        r"Copyright 1995-2017 Mark Adler",
    ]
    FILENAME_PATTERNS = [r"libz.so."]
    VERSION_PATTERNS = [
        r"deflate ([01]+\.[0-9]+\.[0-9]+) ",
        r"inflate ([01]+\.[0-9]+\.[0-9]+) ",
        r"libz.so.([01]+\.[0-9]+\.[0-9]+)",  # patterns like this aren't ideal
    ]
    VENDOR_PRODUCT = [("gnu", "zlib"), ("zlib", "zlib")]


"""
Using filenames (containing patterns like '.so' etc.) in the binaries as VERSION_PATTERNS aren't ideal.
The reason behind this is that these might depend on who packages the file (like it
might work on fedora but not on ubuntu)
"""
