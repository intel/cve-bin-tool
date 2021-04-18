# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dovecot

https://www.cvedetails.com/product/10948/Dovecot-Dovecot.html?vendor_id=6485

"""
from cve_bin_tool.checkers import Checker


class DovecotChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"dovecot"]
    VERSION_PATTERNS = [r"Dovecot v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("dovecot", "dovecot")]
