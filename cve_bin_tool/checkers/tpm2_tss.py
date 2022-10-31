# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for tpm2_software_stack

https://www.cvedetails.com/product/89648/Tpm2-Software-Stack-Project-Tpm2-Software-Stack.html?vendor_id=23886

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Tpm2TssChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"tpm2-tss ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("tpm2_software_stack_project", "tpm2_software_stack")]
