#!/usr/bin/python3

"""
CVE checker for wireshark

https://www.cvedetails.com/product/8292/Wireshark-Wireshark.html?vendor_id=4861

"""
import os
from ..util import regex_find


def get_version(lines, filename):
    """returns version information for wireshark as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be wireshark if wireshark is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of wireshark or contains one
    version gives the actual version number

    VPkg: wireshark, wireshark
    """
    regex = [r"Wireshark ([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    version = regex_find(lines, *regex)

    if "rawshark" in filename:
        version_info["is_or_contains"] = "is"
        version_info["modulename"] = "wireshark"
        version_info["version"] = version
        return version_info

    if version != "UNKNOWN" and "is_or_contains" not in version_info:
        version_info["is_or_contains"] = "contains"
        version_info["modulename"] = "wireshark"
        version_info["version"] = version
        return version_info
    return {}
