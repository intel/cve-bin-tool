# Copyright (C) 2023 SCHUTZWERK GmbH
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dosfstools
https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&orderBy=2.3&keyword=cpe%3A2.3%3Aa%3Adosfstools_project%3Adosfstools&status=FINAL

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DosfstoolsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [
        r"dosfsck",
        r"dosfslabel",
        r"fatlabel",
        r"fsck.fat",
        r"fsck.msdos",
        r"fsck.vfat",
        r"mkdosfs",
        r"mkfs.fat",
        r"mkfs.msdos",
        r"mkfs.vfat",
    ]
    VERSION_PATTERNS = [
        r"fsck.fat (\d+\.\d+)",
        r"mkfs.fat (\d+\.\d+)",
        r"/dosfstools-(\d+\.\d+)",  # match with buildpath if included
    ]
    VENDOR_PRODUCT = [("dosfstools_project", "dosfstools")]
