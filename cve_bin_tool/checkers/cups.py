#!/usr/bin/python3

"""
CVE checker for cups

https://www.cvedetails.com/product/1219/Easy-Software-Products-Cups.html?vendor_id=713

"""
import os
from ..util import regex_find


def get_version(lines, filename):
    """returns version information for cups as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be cups if cups is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of cups or contains one
    version gives the actual version number

    VPkg: easy_software_products, cups
    """
    regex = [r"CUPS v([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    version = regex_find(lines, *regex)

    if "cupsd" in filename:
        version_info["is_or_contains"] = "is"
        version_info["modulename"] = "cups"
        version_info["version"] = version
        return version_info

    if version != "UNKNOWN" and "is_or_contains" not in version_info:
        version_info["is_or_contains"] = "contains"
        version_info["modulename"] = "cups"
        version_info["version"] = version
        return version_info
    return {}
