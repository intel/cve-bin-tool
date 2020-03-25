#!/usr/bin/python3

"""
CVE checker for icu CLI

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-17477/Icu-project.html
"""
import re
from ..util import regex_find


def guess_icu_version_from_content(lines):
    """Guesses the icu version from the file contents"""
    new_guess = ""
    regex_array = [r"icu[_-]([0-9]+\.[0-9]+\.[0-9]+)", r"ICU ([0-9]+\.[0-9]+\.[0-9]+)"]

    match = regex_find(lines, *regex_array)
    if match != "UNKNOWN":
        return match

    pattern1 = re.compile(r"icu[_-](release-)*(0*(?:[1-6][0-9]?))+(\-[0-9]+)*")
    for line in lines:
        match = pattern1.search(line)
        if match:
            new_guess2 = match.group(0).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2
    if len(new_guess) > 0:
        return new_guess[12:].replace("-", ".")
    else:
        return "UNKNOWN"


def get_version(lines, filename):
    """returns version information for icu as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be international_components_for_unicode if icu is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of icu or contains one
    version gives the actual version number

    VPkg: icu-project, international_components_for_unicode
    """
    version_info = dict()
    if "icu" in filename or "international_components_for_unicode" in filename:
        version_info["is_or_contains"] = "is"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "international_components_for_unicode"
        version_info["version"] = guess_icu_version_from_content(lines)

    return version_info
