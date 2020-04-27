#!/usr/bin/python3

"""
CVE checker for bzip2

https://www.cvedetails.com/vulnerability-list/vendor_id-1198/product_id-2068/Bzip-Bzip2.html

"""
import os
from ..util import regex_find


def get_version(lines, filename):
    """returns version information for bzip2 as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be bzip2 if bzip2 is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of bzip2 or contains one
    version gives the actual version number

    VPkg: bzip, bzip2
    """
    regex = [r"bzip2-([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    version = regex_find(lines, *regex)

    if "bzip2" in filename:
        version_info["is_or_contains"] = "is"
        version_info["modulename"] = "bzip2"
        version_info["version"] = version
        return version_info

    if version != "UNKNOWN" and "is_or_contains" not in version_info:
        version_info["is_or_contains"] = "contains"
        version_info["modulename"] = "bzip2"
        version_info["version"] = version
        return version_info
    return {}
