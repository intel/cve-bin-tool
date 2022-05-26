# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for busybox

https://www.cvedetails.com/product/7452/Busybox-Busybox.html?vendor_id=4282

"""
from cve_bin_tool.checkers import Checker


class BusyboxChecker(Checker):
    CONTAINS_PATTERNS = [
        r"BusyBox is a multi-call binary that combines many common Unix",
        r"link to busybox for each function they wish to use and BusyBox",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"BusyBox is copyrighted by many authors between 1998-2015.",
    ]
    FILENAME_PATTERNS = [r"busybox"]
    VERSION_PATTERNS = [r"BusyBox v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("busybox", "busybox")]
