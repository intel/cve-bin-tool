#!/usr/bin/python3

"""
CVE checker for kerberos (CLI/library)

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-42/product_id-61/MIT-Kerberos.html
"""
import re

from ..log import LOGGER
from ..util import regex_find


def guess_krb5_version_from_content(lines):
    """Guesses the krb version from the file contents
    """
    new_guess = ""

    # Library signature looks like "KRB5_BRAND: krb5-1.15.1-final 1.15.1 20170302"
    signatures = [r"KRB5_BRAND: krb5-(\d+\.\d+\.?\d?)-final"]

    match = regex_find(lines, *signatures)
    if match != "UNKNOWN":
        return match

    # CLI signature
    pattern1 = re.compile(r"kerberos 5[_-](appl-)*(1+\.[0-9]+(\.[0-9]+)*)")

    for line in lines:
        match = pattern1.search(line)
        if match:
            new_guess2 = match.group(0).strip()
            if len(new_guess2) > len(new_guess):
                new_guess = new_guess2
    if len(new_guess) > 0:
        return new_guess[9:]
    else:
        return "UNKNOWN"


def guess_contains_kerberos(lines):
    signatures = ["KRB5_BRAND: "]
    for line in lines:
        for signature in signatures:
            if signature in line:
                return True
    return False


def get_version(lines, filename):
    """returns version information for kerberos as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be kerbors if kerberos is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of kerberos or contains one
    version gives the actual version number

    VPkg: mit, kerberos
    VPkg: mit, kerberos_5
    """
    version_info = dict()
    if "kerberos" in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_kerberos(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "kerberos"
        version_info["version"] = guess_krb5_version_from_content(lines)

    # currently we're only detecting kerberos 5, so return a double-version_info list
    # if we ever detect kerberos that's not 5, this if statement will change
    if "is_or_contains" in version_info:
        version_info5 = [dict(), dict()]
        version_info5[0] = version_info
        version_info5[1] = dict()
        version_info5[1]["is_or_contains"] = version_info["is_or_contains"]
        version_info5[1]["modulename"] = "kerberos_5"

        # strip the leading "5-" off the version for 'kerberos_5' if there is one
        # or conversely, add one to the 'kerberos' listing if there isn't
        if version_info["version"][:2] == "5-":
            version_info5[1]["version"] = version_info["version"][2:]
        else:
            version_info5[1]["version"] = version_info["version"]
            version_info5[0]["version"] = "5-{}".format(version_info["version"])
        return version_info5

    return version_info
