# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for freeradius

https://www.cvedetails.com/product/1805/Freeradius-Freeradius.html?vendor_id=1039

"""
from cve_bin_tool.checkers import Checker


class FreeradiusChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Application and libfreeradius-server magic number (commit) mismatch.  application: %lx library: %lx",
        r"Application and libfreeradius-server magic number (prefix) mismatch.  application: %x library: %x",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"Application and libfreeradius-server magic number (version) mismatch.  application: %lx library: %lx",
        # r"FreeRADIUS Version ([0-9]+\.[0-9]+\.[0-9]+), for host aarch64-redhat-linux-gnu",
    ]
    FILENAME_PATTERNS = [r"radiusd"]
    VERSION_PATTERNS = [r"FreeRADIUS Version ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("freeradius", "freeradius")]
