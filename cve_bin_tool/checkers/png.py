#!/usr/bin/python3

"""
CVE checker for libpng

References:
http://www.cvedetails.com/vulnerability-list/vendor_id-7294/Libpng.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=7294&product_id=0&version_id=&orderby=3&cvssscoremin=0
"""
from ..util import regex_find


def guess_contains_png(lines):
    """Tries to determine if a file includes png
    """
    for line in lines:
        if "libpng error: %s, offset=%d" in line:
            return 1
        if (
            "Application uses deprecated png_write_init() and should be recompiled"
            in line
        ):
            return 1
        if "libpng version " in line:
            return 1
    return 0


def get_version(lines, filename):
    """returns version information for png as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be png if png is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of png or contains one
    version gives the actual version number

    VPkg: libpng, libpng
    """
    regex = [r"libpng version ([0-9]+\.[0-9]+\.[0-9]+) -"]
    version_info = dict()
    if "libpng.so." in filename or "libpng16.so." in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_png(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "png"
        version_info["version"] = regex_find(lines, *regex)

    return version_info
