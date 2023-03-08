# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libvirt

https://www.cvedetails.com/product/15743/Libvirt-Libvirt.html?vendor_id=8917
https://www.cvedetails.com/product/20594/Redhat-Libvirt.html?vendor_id=25

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibvirtChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [
        r"libvirtd",
        r"libvirt.so",
    ]
    VERSION_PATTERNS = [
        r"LIBVIRT_PRIVATE_([0-9]+\.[0-9]+\.[0-9]+)",
        r"libvirt version: ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("libvirt", "libvirt"), ("redhat", "libvirt")]
