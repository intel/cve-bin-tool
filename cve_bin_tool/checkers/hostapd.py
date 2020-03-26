#!/usr/bin/python3

"""
CVE checker for hostapd

https://www.cvedetails.com/product/22495/W1.fi-Hostapd.html?vendor_id=12005

"""
import os
from ..util import regex_find


def get_version(lines, filename):
    """returns version information for hostapd as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be hostapd if hostapd is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of hostapd or contains one
    version gives the actual version number

    VPkg: w1.fi, hostapd
    """
    regex = [r"hostapd v([0-9]+\.[0-9]+)"]
    version_info = dict()
    version = regex_find(lines, *regex)

    if "hostapd" in filename:
        version_info["is_or_contains"] = "is"
        version_info["modulename"] = "hostapd"
        version_info["version"] = version
        return version_info

    if version != "UNKNOWN" and "is_or_contains" not in version_info:
        version_info["is_or_contains"] = "contains"
        version_info["modulename"] = "hostapd"
        version_info["version"] = version
        return version_info
    return {}
