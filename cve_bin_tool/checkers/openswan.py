#!/usr/bin/python3

"""
CVE checker for openswan

https://www.cvedetails.com/product/57217/Xelerance-Openswan.html?vendor_id=20146

"""
import os
from ..util import regex_find


def get_version(lines, filename):
    """returns version information for openswan as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be openswan if openswan is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of openswan or contains one
    version gives the actual version number

    VPkg: xelerance, openswan
    """
    regex = [r"Openswan ([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()

    binary_names = [
        "klipsdebug",
        "showhostkey",
        "ranbits",
        "eroute",
        "showpolicy",
        "spigrp",
        "pluto",
        "ikeping",
        "rsasigkey",
    ]

    version = regex_find(lines, *regex)

    for name in binary_names:
        if name in filename:
            version_info["is_or_contains"] = "is"
            version_info["modulename"] = "openswan"
            version_info["version"] = version
            return version_info

    if version != "UNKNOWN" and "is_or_contains" not in version_info:
        version_info["is_or_contains"] = "contains"
        version_info["modulename"] = "openswan"
        version_info["version"] = version
        return version_info
    return {}
