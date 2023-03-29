# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for pigz

https://www.cvedetails.com/product/27527/?q=Pigz

"""
from cve_bin_tool.checkers import Checker


class PigzChecker(Checker):
    CONTAINS_PATTERNS = [
        r"-L, --license        Display the pigz license and quit",
        r"-V  --version        Show the version of pigz",
        r"cannot provide files in PIGZ environment variable",
        r"specified, stdin will be compressed to stdout. pigz does what gzip does,",
    ]
    FILENAME_PATTERNS = [r"pigz"]
    VERSION_PATTERNS = [r"pigz ([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("zlib", "pigz")]
