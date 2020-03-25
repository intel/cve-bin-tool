#!/usr/bin/python3
# pylint: disable=invalid-name

"""
CVE checker for libjpg-turbo

Note that this file is named libjpeg.py instead of libjpeg-turbo.py to avoid an issue
with loading the module.

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-17075/product_id-40849/Libjpeg-turbo-Libjpeg-turbo.html
"""
import re


def guess_libjpeg_turbo_version_from_content(lines):
    """Guesses the libjpeg-turbo version from the file contents
    """
    new_guess = ""
    # fedora string looks like libjpeg-turbo version 2.0.0 (build 20180730)
    pattern1 = re.compile(r"libjpeg-turbo version ([0-9]\.[0-9]\.[0-9])")
    pattern2 = re.compile(r"LIBJPEG(TURBO)?_([0-9]+\.[0-9]+\.?[0-9]?)")

    for line in lines:
        match = pattern1.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2

        match = pattern2.search(line)
        if match:
            new_guess2 = match.group(2).strip()  # note group different here
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2

    if len(new_guess) > 0:
        return new_guess
    else:
        return "UNKNOWN"


def guess_contains_libjpeg_turbo(lines):
    """Tries to determine if a file includes libjpeg-turbo
    """
    for line in lines:
        if "LIBJPEG" in line:
            return 1
        if "Caution: quantization tables are too coarse for baseline JPEG" in line:
            return 1
        if "Invalid JPEG file structure: two SOF markers" in line:
            return 1
    return 0


def get_version(lines, filename):
    """returns version information for libjpg-turbo as found in a given file.

    VPkg: libjpeg-turbo, libjpeg-turbo
    """
    version_info = dict()
    if "libjpg.so." in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_libjpeg_turbo(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "libjpeg-turbo"
        version_info["version"] = guess_libjpeg_turbo_version_from_content(lines)

    return version_info
