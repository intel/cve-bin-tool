# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import re

"""
A class for comparing arbitrary versions of products.

Splits versions up using common whitespace delimiters and also splits out letters
so that things like openSSL's 1.1.1y type of version will work too.

This handles some pretty strange edge cases.  See the test_version_compare.py
and inline comments for details

"""


class CannotParseVersionException(Exception):
    """
    Thrown if the version doesn't comply with our expectations
    """


class UnknownVersion(Exception):
    """
    Thrown if version is null or "unknown".
    """


def parse_version(version_string: str):
    """
    Splits a version string into an array for comparison.
    This includes dealing with some letters.

    e.g. 1.1.1a would become [1, 1, 1, a]
    """

    if not version_string or version_string.lower() == "unknown":
        raise UnknownVersion(f"version string = {version_string}")

    versionString = version_string.strip()

    # convert all non alpha-numeric characters to be treated like . below
    # we could switch to a re split but it seems to leave blanks so this is less hassle
    # Note: This expression may need improvement if we need to handle unicode
    versionString = re.sub("[^0-9a-zA-Z]+", ".", versionString)

    # We originally had hash detection in here, but it turns out very few companies
    # use hashes in ranges but more used dates that were getting caught in the same net
    # (see https://github.com/intel/cve-bin-tool/pull/3694 )
    # Hash deteciton may be useful in the future but it would have to be better defined.

    # otherwise, split up letters and numbers into separate units for compare
    versionString = re.sub("([a-zA-Z]+)", r".\1.", versionString)

    # Clean up any duplicate . and then split
    versionString = re.sub(r"\.+", ".", versionString)
    split_version = versionString.strip(".").split(".")

    return split_version


def version_compare(v1: str, v2: str):
    """
    Compare two versions by converting them to arrays

    returns 0 if they're the same.
    returns 1 if v1 > v2
    returns -1 if v1 < v2
    """
    v1_array = parse_version(v1)
    v2_array = parse_version(v2)

    # We'll treat the following strings as pre-releases.
    pre_release_words = {"pre", "rc", "alpha", "beta", "dev"}

    for i in range(len(v1_array)):
        if len(v2_array) > i:
            # If it's all numbers, cast to int and compare
            if v1_array[i].isnumeric() and v2_array[i].isnumeric():
                if int(v1_array[i]) > int(v2_array[i]):
                    return 1
                if int(v1_array[i]) < int(v2_array[i]):
                    return -1

            # If they're letters do a string compare.
            # This might be a bad choice in some cases: Do we want ag < z?
            # I suspect projects using letters in version names may not use ranges in nvd
            # for this reason (e.g. openssl)
            # Converting to lower() so that 3.14a == 3.14A
            # but this may not be ideal in all cases
            elif v1_array[i].isalpha() and v2_array[i].isalpha():
                # allow pre-releases to come before arbitrary letters.
                if (
                    v1_array[i] in pre_release_words
                    and v2_array[i] not in pre_release_words
                ):
                    return -1
                if (
                    v1_array[i] not in pre_release_words
                    and v2_array[i] in pre_release_words
                ):
                    return 1

                # Note that if both are in the pre-release list we alpha compare
                if v1_array[i].lower() > v2_array[i].lower():
                    return 1
                if v1_array[i].lower() < v2_array[i].lower():
                    return -1

            else:
                # They are not the same type, and we're comparing mixed letters and numbers.
                # We treat letters less than numbers

                # This may cause false positives with some distro numbers
                # e.g. 1.4.ubuntu8 may have fixed some issues in 1.4,
                # But since we can't be sure we'll return the 'safer' result
                # and let users triage themselves.
                if v1_array[i].isalnum() and v2_array[i].isnumeric():
                    return -1
                elif v1_array[i].isnumeric() and v2_array[i].isalnum():
                    return 1

                # And if all else fails, just compare the strings
                if v1_array[i] > v2_array[i]:
                    return 1
                if v1_array[i] < v2_array[i]:
                    return -1

        else:
            # v1 has more digits than v2
            # Check to see if v1's something that looks like a pre-release (a2, dev8, rc4)
            # e.g. 4.5.a1 would be less than 4.5
            if v1_array[i] in pre_release_words:
                return -1

            # Otherwise, v1 has more digits than v2 and the previous ones matched,
            # so it's probably later.  e.g. 1.2.3 amd 1.2.q are both > 1.2
            return 1

    # if we made it this far and they've matched, see if there's more stuff in v2
    # e.g. 1.2.3 or 1.2a comes after 1.2
    if len(v2_array) > len(v1_array):
        # special case: if v2 declares itself a post-release, we'll say it's bigger than v1
        if v2_array[len(v1_array)].startswith("post"):
            return -1

        # if what's in v2 next looks like a pre-release then we'll
        # claim v1 is still bigger, otherwise we'll say v2 is.
        if v2_array[len(v1_array)] in pre_release_words:
            return 1

        return -1

    return 0


class Version(str):
    """
    A class to make version comparisons look more pretty:

    Version("1.2") > Version("1.1")
    """

    def __cmp__(self, other):
        """compare"""
        return version_compare(self, other)

    def __lt__(self, other):
        """<"""
        return bool(version_compare(self, other) < 0)

    def __le__(self, other):
        """<="""
        return bool(version_compare(self, other) <= 0)

    def __gt__(self, other):
        """>"""
        return bool(version_compare(self, other) > 0)

    def __ge__(self, other):
        """>="""
        return bool(version_compare(self, other) >= 0)

    def __eq__(self, other):
        """=="""
        return bool(version_compare(self, other) == 0)

    def __ne__(self, other):
        """!="""
        return bool(version_compare(self, other) != 0)

    def __repr__(self):
        """print the version string"""
        return f"Version: {self} aka {parse_version(self)}"
