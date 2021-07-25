# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for kexec-tools

https://www.cvedetails.com/product/27100/?q=Kexec-tools

"""
from cve_bin_tool.checkers import Checker


class KexectoolsChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"kexec"]
    VERSION_PATTERNS = [r"kexec-tools ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("redhat", "kexec-tools")]
