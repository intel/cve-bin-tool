#!/usr/bin/python3

"""
CVE checker for zlib
--------
References:
http://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-1820/GNU-Zlib.html
https://zlib.net/ChangeLog.txt

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=72&product_id=1820&version_id=&orderby=2&cvssscoremin=0
"""
import re

def guess_zlib_version_from_content(lines):
    """Guesses the zlib version from the file contents
    """
    new_guess = ""
    pattern1 = re.compile(r"deflate ([01]+\.[0-9]+\.[0-9]+) ")
    pattern2 = re.compile(r"inflate ([01]+\.[0-9]+\.[0-9]+) ")

    for line in lines:
        match = pattern1.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2
        match = pattern2.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2

    return new_guess

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

    version_info = dict()
    if "libz.so." in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_zlib(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "zlib"
        version_info["version"] = guess_zlib_version_from_content(lines)

# FIXME: the original code has a version check as follows that we might
# need to include here.
#     if is_zlib == 1 and (zlib_version not in "1.2.8") and (zlib_version not in "1.2.5") and (zlib_version not in "1.2.3"):
#           # print cve info

    return version_info
