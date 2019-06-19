#!/usr/bin/python3

"""
CVE checker for libxml2

References:
http://www.cvedetails.com/vulnerability-list/vendor_id-1962/product_id-3311/Xmlsoft-Libxml2.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=1962&product_id=3311&version_id=&orderby=2&cvssscoremin=0
"""
import re


def guess_xml2_version_from_content(lines):
    """Guesses the xml2 version from the file contents
    """
    new_guess = ""
    pattern1 = re.compile(r"\/libxml2\-([0-9]+\.[0-9]+\.[0-9]+)\/")
    pattern2 = re.compile(r"\\libxml2\-([0-9]+\.[0-9]+\.[0-9]+)\\")
    # fedora 29 string looks like libxml2.so.2.9.8-2.9.8-4.fc29.x86_64.debug
    pattern3 = re.compile(r"libxml2.so.([0-9]+\.[0-9]+\.[0-9]+)")

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
        if line == "20901":
            new_guess = "2.9.1"
        if line == "20902":
            new_guess = "2.9.2"
        if line == "20903":
            new_guess = "2.9.3"
        if line == "20904":
            new_guess = "2.9.4"

        match = pattern3.search(line)
        if match:
            new_guess2 = match.group(1).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2
    return new_guess


def guess_contains_xml2(lines):
    """Tries to determine if a file includes xml2
    """
    for line in lines:
        if "Internal error, xmlCopyCharMultiByte 0x%X out of bound" in line:
            return 1
        if "xmlNewElementContent : name != NULL !" in line:
            return 1
        if (
            "xmlRelaxNG: include %s has a define %s but not the included grammar"
            in line
        ):
            return 1
    return 0


def get_version(lines, filename):
    """returns version information for xml2 as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be xml2 if xml2 is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of xml2 or contains one
    version gives the actual version number

    VPkg: xmlsoft, libxml2
    """
    version_info = dict()
    if "libxml2.so." in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_xml2(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "xml2"
        version_info["version"] = guess_xml2_version_from_content(lines)

    return version_info
