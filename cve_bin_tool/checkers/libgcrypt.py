# pylint: disable=invalid-name
"""
CVE checker for libgcrypt

https://www.cvedetails.com/product/25777/Gnupg-Libgcrypt.html?vendor_id=4711
"""
from ..util import regex_find


def guess_contains_libcrypt(lines):
    """Tries to determine if a file includes libgcrypt
    """
    for line in lines:
        if "fork detection failed" in line:
            return 1
        if "too many random bits requested" in line:
            return 1
        if "severe error getting random" in line:
            return 1
    return 0


def get_version(lines, filename):
    """returns version information for libgcrypt as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be libgcrypt if libgcrypt is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of libgcrypt or contains one
    version gives the actual version number

    VPkg: gnupg, libgcrypt
    """
    regex = [r"Libgcrypt ([01]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    if "libgcrypt.so." in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_libcrypt(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "libgcrypt"
        version_info["version"] = regex_find(lines, *regex)
    return version_info
