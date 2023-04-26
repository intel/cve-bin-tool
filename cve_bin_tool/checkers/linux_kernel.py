# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for linux_kernel

https://www.cvedetails.com/product/47/Linux-Linux-Kernel.html?vendor_id=33

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LinuxKernelChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"vermagic=([0-9]+\.[0-9]+\.[0-9]+)",
        r"\r?\n(?:Linux version |)([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9 ,+@\-\.\(\)]* #[0-9] [a-zA-Z]",
    ]
    VENDOR_PRODUCT = [("linux", "linux_kernel")]
