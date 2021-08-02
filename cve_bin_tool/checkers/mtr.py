# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mtr

https://www.cvedetails.com/product/2103/?q=MTR

"""
from cve_bin_tool.checkers import Checker


class MtrChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Mtr_Version,Start_Time,Status,Host,Hop,Ip,",
        r"protocol unsupported by mtr-packet interface",
    ]
    FILENAME_PATTERNS = [r"mtr"]
    VERSION_PATTERNS = [r"mtr ([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("matt_kimball_and_roger_wolff", "mtr"), ("mtr", "mtr")]
