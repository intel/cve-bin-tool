#!/usr/bin/python3

"""
CVE checker for libtiff

http://www.cvedetails.com/vulnerability-list/vendor_id-2224/product_id-3881/Libtiff-Libtiff.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=2224&product_id=3881&version_id=&orderby=3&cvssscoremin=0
"""
from ..util import regex_find


def guess_contains_tiff(lines):
    """Tries to determine if a file includes tiff
    """
    for line in lines:
        if "LIBTIFF, Version " in line:
            return 1
        if "Unknown TIFF resolution unit %d ignored" in line:
            return 1
        if (
            'TIFF directory is missing required "StripByteCounts" field, calculating from imagelength'
            in line
        ):
            return 1
    return 0


def get_version(lines, filename):
    """returns version information for tiff as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be tiff if tiff is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of tiff or contains one
    version gives the actual version number

    VPkg: libtiff, libtiff
    """
    regex = [r"LIBTIFF, Version ([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    if "libtiff.so." in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_tiff(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "tiff"
        version_info["version"] = regex_find(lines, *regex)

    return version_info
