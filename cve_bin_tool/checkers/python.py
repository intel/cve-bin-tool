#!/usr/bin/env python3
"""
CVE checker for Python
References:
https://www.cvedetails.com/vulnerability-list/vendor_id-10210/product_id-18230/Python-Python.html


"""
from ..util import regex_find


def guess_contains_python(lines):
    """Tries to determine if a file includes python
    """
    for line in lines:
        if "Fatal Python error: unable to decode the command line argument" in line:
            return 1
        if "CPython" in line:
            return 1
        if "Internal error in the Python interpreter" in line:
            return 1
    return 0


def guess_version(lines):
    """
    Tries to determine the version of python.
    """
    # we will try to find python3+ as well as python2+

    # currently regex will probably find a single string "lib/python3.6" where 3.6 is the version similarly "lib/python2.7" where 2.7 is the version
    regex = [r"python([23]+\.[0-9])"]
    guess = regex_find(lines, *regex)

    # we will check if the guess returned some version probably 3.6 or 2.7 in our example
    if guess != "UNKNOWN":

        # we will update our regex to something more precise 3.6.d where d is unknown and we will find d. which will return 3.6.9 or some other version
        version_regex = [r"([%s]+\.[%s]+\.[0-9])" % (guess[0], guess[2])]
        new_guess = regex_find(lines, *version_regex)

        # we will return this result
        return new_guess

    # else guess was unknown so we update our regex
    else:
        version_regex = [
            r"Version: ([23]+\.[0-9]+\.[0-9])+",
            r"version: ([23]+\.[0-9]+\.[0-9])+",
            r"Python ([23]+\.[0-9]+\.[0-9])+",
        ]
        new_guess = regex_find(lines, *version_regex)

        return new_guess


def get_version(lines, filename):
    """
    Returns a version information for python 3

    VPkg: python_software_foundation, python
    VPkg: python, python
    """
    version_info = dict()
    if "python" in filename.lower():
        version_info["is_or_contains"] = "is"

    elif guess_contains_python(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "python"
        version_info["version"] = guess_version(lines)

    return version_info
