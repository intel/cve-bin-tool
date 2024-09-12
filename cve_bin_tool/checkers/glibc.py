# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for glibc CLI

References:
https://www.gnu.org/software/glibc/
https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-767/GNU-Glibc.html


"""
from cve_bin_tool.checkers import Checker


class GlibcChecker(Checker):
    CONTAINS_PATTERNS = [
        r"The following command substitution is needed to make ldd work in SELinux",
        r"environments where the RTLD might not have permission to write to the",
        r"Valid options for the LD_DEBUG environment variable are:",
        r"To direct the debugging output into a file instead of standard output",
        r"Mandatory or optional arguments to long options are also mandatory or optional for any corresponding short options.",
    ]
    FILENAME_PATTERNS = [
        r"ldd",
        r"libc6",
        r"glibc-source",
        r"glibc",
        r"nscd",
        r"libc\.so",
        r"libc-([012](\.[0-9]+){1,2})\.so",
        r"ld-([012](\.[0-9]+){1,2})\.so",
    ]
    VERSION_PATTERNS = [
        r"GNU C Library \([a-zA-Z0-9 \+\-\.]*\) (?:release|stable) release version ([012](\.[0-9]+){1,2})",
        r"GLIBC ([012](\.[0-9]+){1,2})[a-z0-9+\-]*\) \r?\n",
    ]
    VENDOR_PRODUCT = [("gnu", "glibc")]
