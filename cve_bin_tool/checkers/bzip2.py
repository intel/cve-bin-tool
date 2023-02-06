# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for bzip2

https://www.cvedetails.com/vulnerability-list/vendor_id-1198/product_id-2068/Bzip-Bzip2.html

"""
from cve_bin_tool.checkers import Checker


class Bzip2Checker(Checker):
    CONTAINS_PATTERNS = [
        r"bzip2recover ([0-9]+\.[0-9]+\.[0-9]+): extracts blocks from damaged .bz2 files.",
        r"%s: BZ_MAX_HANDLED_BLOCKS in bzip2recover.c, and recompile.",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"in the bzip2-1.0.6 source distribution.", # present only .rpm
    ]
    FILENAME_PATTERNS = [r"bzip2"]
    VERSION_PATTERNS = [
        r"bzip2-([0-9]+\.[0-9]+\.[0-9]+)",
        r"bzip2recover ([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+), [a-zA-Z0-9-]*\r?\nbzip2",
    ]
    VENDOR_PRODUCT = [("bzip", "bzip2")]
