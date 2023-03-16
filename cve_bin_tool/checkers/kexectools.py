# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for kexec-tools

https://www.cvedetails.com/product/27100/?q=Kexec-tools
https://www.cvedetails.com/product/121743/Kexec-tools-Project-Kexec-tools.html?vendor_id=28449

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class KexectoolsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"kexec"]
    VERSION_PATTERNS = [r"kexec-tools ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("kexec-tools_project", "kexec-tools"), ("redhat", "kexec-tools")]
