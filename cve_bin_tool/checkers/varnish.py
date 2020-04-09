#!/usr/bin/python3

"""
CVE checker for varnish
https://www.cvedetails.com/vulnerability-list/vendor_id-12937/product_id-26407/Varnish-cache-Varnish.html
"""
import os
from ..util import regex_find


def get_version(lines, filename):
    """returns version information for varnish as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]
    modulename will be varnish if varnish is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of varnish or contains one
    version gives the actual version number
    VPkg: varnish-cache, varnish
    """
    regex = [r"varnish-([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    version = regex_find(lines, *regex)

    if "varnish" in filename:
        version_info["is_or_contains"] = "is"
        version_info["modulename"] = "varnish"
        version_info["version"] = version
        return version_info

    if version != "UNKNOWN" and "is_or_contains" not in version_info:
        version_info["is_or_contains"] = "contains"
        version_info["modulename"] = "varnish"
        version_info["version"] = version
        return version_info
    return {}
