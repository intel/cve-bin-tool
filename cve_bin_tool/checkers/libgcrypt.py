# pylint: disable=invalid-name
"""
CVE checker for libgcrypt

https://www.cvedetails.com/product/25777/Gnupg-Libgcrypt.html?vendor_id=4711
"""
from . import Checker


class LibgcryptChecker(Checker):
    CONTAINS_PATTERNS = [
        "fork detection failed",
        "too many random bits requested",
        "severe error getting random",
    ]
    FILENAME_PATTERNS = [r"libgcrypt.so."]
    VERSION_PATTERNS = [r"Libgcrypt ([01]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gnupg", "libgcrypt")]
