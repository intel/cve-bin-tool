#!/usr/bin/python3

"""
CVE checker for strongswan

https://www.cvedetails.com/product/3992/Strongswan-Strongswan.html?vendor_id=2278

"""
import os
from ..util import regex_find


def get_version(lines, filename):
    """returns version information for strongswan as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be strongswan if strongswan is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of strongswan or contains one
    version gives the actual version number

    VPkg: strongswan, strongswan
    """
    regex = [r"strongSwan ([0-9]+\.[0-9]+\.[0-9])"]
    version_info = dict()
    version = regex_find(lines, *regex)

    if "libcharon.so" in filename:
        version_info["is_or_contains"] = "is"
        version_info["modulename"] = "strongswan"
        version_info["version"] = version
        return version_info

    if version != "UNKNOWN" and "is_or_contains" not in version_info:
        version_info["is_or_contains"] = "contains"
        version_info["modulename"] = "strongswan"
        version_info["version"] = version
        return version_info
    return {}
