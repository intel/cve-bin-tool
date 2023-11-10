# Copyright (C) 2023 SCHUTZWERK GmbH
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for debianutils

References:
https://salsa.debian.org/debian/debianutils

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DebianutilsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [
        r"run-parts",
        r"tempfile",
        r"ischroot",
        r"installkernel",
        r"savelog",
        r"which.debianutils",
        r"add-shell",
        r"remove-shell",
        r"update-shells",
    ]
    VERSION_PATTERNS = [
        r"\r?\nDebian run-parts program, version\s([0-9]+\.[0-9]+)",
        r"\r?\ntempfile\s([0-9]+\.[0-9]+)",
        r"\r?\nDebian ischroot, version\s([0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("debian", "debianutils")]
