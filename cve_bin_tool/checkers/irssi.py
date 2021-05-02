# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for irssi

https://www.cvedetails.com/product/2131/Irssi-Irssi.html?vendor_id=1229

"""
from cve_bin_tool.checkers import Checker


class IrssiChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"irssi"]
    VERSION_PATTERNS = [r"irssi ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("irssi", "irssi")]
