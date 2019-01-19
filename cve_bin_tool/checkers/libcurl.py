#!/usr/bin/python3

"""
CVE checker for libcurl

References:
https://curl.haxx.se/docs/security.html
http://www.cvedetails.com/vulnerability-list/vendor_id-12682/Haxx.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=12682&product_id=0&version_id=0&orderby=3&cvssscoremin=0

Note: Some of the "first vulnerable in" data may not be entered correctly.
"""
import re

def guess_curl_version_from_content(lines):
    """Guesses the curl version from the file contents
    """
    new_guess = ""
    pattern1 = re.compile(r"CLIENT libcurl ([678]+\.[0-9]+\.[0-9]+)")

    for line in lines:
        match = pattern1.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2

    return new_guess

def guess_contains_curl(lines):
    """Tries to determine if a file includes curl
    """
    for line in lines:
        if "An unknown option was passed in to libcurl" in line:
            return 1
        if "A requested feature, protocol or option was not found built-in in this libcurl due to a build-time decision." in line:
            return 1
        if "CLIENT libcurl 7." in line:
            return 1
    return 0

def get_version(lines, filename):
    """returns version information for curl as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be curl if curl is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of curl or contains one
    version gives the actual version number

    VPkg: haxx, curl
    VPkg: haxx, libcurl
    """
    version_info = dict()
    if "libcurl.so." in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_curl(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "curl"
        version_info["version"] = guess_curl_version_from_content(lines)

    return version_info

