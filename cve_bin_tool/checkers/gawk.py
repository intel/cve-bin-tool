# Copyright (C) 2023 SCHUTZWERK GmbH
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for gawk

References:
http://savannah.gnu.org/projects/gawk/
https://www.gnu.org/software/gawk/
"""

from cve_bin_tool.checkers import Checker


class GawkChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [
        r"gawk",
    ]
    VERSION_PATTERNS = [r"GNU Awk (\d+\.\d+\.\d+)\r?\n"]
    VENDOR_PRODUCT = [("gnu", "gawk")]
