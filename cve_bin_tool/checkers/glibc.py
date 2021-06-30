# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import re

from packaging.version import parse

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
        r"GNU C Library \(GNU libc\) stable release version ([012](\.[0-9]+){1,2})",
        r"glibc ([012](\.[0-9]+){1,2})",
        r"libc-([012](\.[0-9]+){1,2})\.so\.debug",  # patterns like this aren't ideal (check the end of the file)
        r"ld-([012]\.[0-9]+)\.so\.debug",  # patterns like this aren't ideal
        r"libanl-([012](\.[0-9]+){1,2})\.so\.debug",  # patterns like this aren't ideal
        r"ld-([012](\.[0-9]+){1,2})\.so\.debug",  # patterns like this aren't ideal
    ]
    VENDOR_PRODUCT = [("gnu", "glibc")]

    def get_version(self, lines, filename):

        version_info = super().get_version(lines, filename)
        version_patterns = [r"GLIBC_([0-9]+\.[0-9]+)", r"GLIBC ([0-9]+\.[0-9]+)"]
        if "is_or_contains" in version_info and version_info["version"] == "UNKNOWN":
            # GLIBC* pattern repeats itself a couple of times. Use the latest version value if this pattern exists
            recent = ""
            version_list = []

            for line in lines:
                for pattern in version_patterns:
                    match = re.search(pattern, line)
                    if match:
                        version_list.append(match.group(1).strip())

            if version_list:
                # Find the latest version string pattern
                recent = version_list[0]
                for v in version_list:
                    if parse(recent) < parse(v):
                        recent = v
                version_info["version"] = recent

        return version_info


"""
Using filenames (containing patterns like '.so' etc.) in the binaries as VERSION_PATTERNS aren't ideal.
The reason behind this is that these might depend on who packages the file (like it 
might work on fedora but not on ubuntu)
"""
