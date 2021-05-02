# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for busybox

https://www.cvedetails.com/product/7452/Busybox-Busybox.html?vendor_id=4282

"""
from cve_bin_tool.checkers import Checker


class BusyboxChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"busybox"]
    VERSION_PATTERNS = [r"BusyBox v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("busybox", "busybox")]
