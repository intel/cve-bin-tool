#!/usr/bin/python3

"""
CVE checker for glibc CLI

References:
https://www.gnu.org/software/glibc/
https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-767/GNU-Glibc.html


"""
from . import Checker


class GlibcChecker(Checker):

    CONTAINS_PATTERNS = [
        r"The following command substitution is needed to make ldd work in SELinux",
        r"environments where the RTLD might not have permission to write to the",
    ]
    FILENAME_PATTERNS = [
        r"ldd",
        r"libc6",
        r"glibc-source",
        r"glibc",
        r"nscd",
        r"libc.so.",
    ]
    VERSION_PATTERNS = [r"GLIBC_([0-9]+\.[0-9]+)", r"GLIBC ([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gnu", "glibc")]
