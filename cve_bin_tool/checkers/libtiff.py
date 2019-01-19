#!/usr/bin/python3

"""
CVE checker for libtiff

http://www.cvedetails.com/vulnerability-list/vendor_id-2224/product_id-3881/Libtiff-Libtiff.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=2224&product_id=3881&version_id=&orderby=3&cvssscoremin=0
"""

import re

def guess_tiff_version_from_content(lines):
    """Guesses the tiff version from the file contents
    """
    new_guess = ""
    pattern1 = re.compile(r"LIBTIFF, Version ([0-9]+\.[0-9]+\.[0-9]+)")

    for line in lines:
        match = pattern1.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2

    return new_guess

def guess_contains_tiff(lines):
    """Tries to determine if a file includes tiff
    """
    for line in lines:
        if "LIBTIFF, Version " in line:
            return 1
        if "Unknown TIFF resolution unit %d ignored" in line:
            return 1
        if "TIFF directory is missing required \"StripByteCounts\" field, calculating from imagelength" in line:
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
    version_info = dict()
    if "libtiff.so." in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_tiff(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "tiff"
        version_info["version"] = guess_tiff_version_from_content(lines)

    return version_info

