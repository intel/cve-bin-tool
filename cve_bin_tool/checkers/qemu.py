# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for qemu

https://www.cvedetails.com/product/12657/Qemu-Qemu.html?vendor_id=7506

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class QemuChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = [r"qemu"]
    VERSION_PATTERNS = [
        r"QEMU ([0-9]+.[0-9]+(.[0-9]+)?)",
        r"QEMU v([0-9]+.[0-9]+(.[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [("xen", "qemu"), ("qemu", "qemu")]
