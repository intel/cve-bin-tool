#!/usr/bin/python3

"""
CVE checker for zlib
--------
References:
http://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-1820/GNU-Zlib.html
https://zlib.net/ChangeLog.txt

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=72&product_id=1820&version_id=&orderby=2&cvssscoremin=0
"""
from ..util import regex_find


def guess_contains_zlib(lines):
    """Tries to determine if a file includes zlib
    """
    for line in lines:
        if "deflate" in line and "Copyright 1995-2005 Jean-loup Gailly" in line:
            return 1
        if "Copyright 1995-2005 Mark Adler" in line and "inflate" in line:
            return 1
        if "too many length or distance symbols" in line:
            return 1
    return 0


def get_version(lines, filename):
    """returns version information for zlib as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be zlib if zlib is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of zlib or contains one
    version gives the actual version number

    VPkg: gnu, zlib
    """
    regex = [r"deflate ([01]+\.[0-9]+\.[0-9]+) ", r"inflate ([01]+\.[0-9]+\.[0-9]+) "]
    version_info = dict()
    if "libz.so." in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_zlib(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "zlib"
        version_info["version"] = regex_find(lines, *regex)

    return version_info
