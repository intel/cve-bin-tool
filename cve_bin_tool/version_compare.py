# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import re

"""
A class for comparing arbitrary versions of products.

Splits versions up using common whitespace delimiters and also splits out letters
so that things like openSSL's 1.1.1y type of version will work too.

This may need some additional smarts for stuff like "rc" or "beta" and potentially for
things like distro versioning.  I don't know yet.
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
    versionArray = []

    # convert all non alpha-numeric characters to be treated like . below
    # we could switch to a re split but it seems to leave blanks so this is less hassle
    versionString = re.sub("[^0-9a-zA-Z]+", ".", versionString)

    # Note: This expression may need improvement if we need to handle unicode

    # remove any trailing . then split
    versionString = versionString.strip(".")
    split_version = versionString.split(".")

    # if the whole string was numeric then we're done and you can move on
    if versionString.isnumeric():
        versionArray = split_version
        return versionArray

    # Go through and split up anything like 6a in to 6 and a
    number_letter = re.compile("^([0-9]+)([a-zA-Z]+)$")
    letter_number = re.compile("^([a-zA-Z]+)([0-9]+)$")
    for section in split_version:
        # if it's all letters or all numbers, just add it to the array
        if section.isnumeric() or section.isalpha():
            versionArray.append(section)

        # if it looks like 42a split out the letters and numbers
        # We will treat 42a as coming *after* version 42.
        elif re.match(number_letter, section):
            result = re.findall(number_letter, section)

            # We're expecting a result that looks like [("42", "a")] but let's verify
            # and then add it to the array
            if len(result) == 1 and len(result[0]) == 2:
                versionArray.append(result[0][0])
                versionArray.append(result[0][1])
            else:
                raise CannotParseVersionException(f"version string = {versionString}")

        # if it looks like rc1 or dev7 we'll leave it together as it may be some kind of pre-release
        # and we'll probably want to handle it specially in the compare.
        # We need to threat 42dev7 as coming *before* version 42.
        elif re.match(letter_number, section):
            versionArray.append(section)

        # It's not a "pure" alpha or number string, it's not something like rc12 or 44g

        # It could be a hash, which we can't string compare without knowledge of the product.
        # It could also be a distro release string like deb8u5, which we could compare
        # but the data may not be useful or usable in context.
        else:
            # If it's the last part of the version just drop it silently
            # we could log these but I suspect it would be very noisy
            if section == split_version[len(split_version) - 1]:
                pass

            # if it's not, raise an exception because we should probably examine it
            elif versionString != ".":
                raise CannotParseVersionException(f"version string = {versionString}")

    return versionArray


def version_compare(v1: str, v2: str):
    """
    Compare two versions by converting them to arrays

    returns 0 if they're the same.
    returns 1 if v1 > v2
    returns -1 if v1 < v2findall
    n
    """
    v1_array = parse_version(v1)
    v2_array = parse_version(v2)

    for i in range(len(v1_array)):
        if len(v2_array) > i:
            # If it's all numbers, cast to int and compare
            if v1_array[i].isnumeric() and v2_array[i].isnumeric():
                if int(v1_array[i]) > int(v2_array[i]):
                    return 1
                if int(v1_array[i]) < int(v2_array[i]):
                    return -1

            # If they're letters just do a string compare, I don't have a better idea
            # This might be a bad choice in some cases: Do we want ag < z?
            # I suspect projects using letters in version names may not use ranges in nvd
            # for this reason (e.g. openssl)
            # Converting to lower() so that 3.14a == 3.14A
            # but this may not be ideal in all cases
            elif v1_array[i].isalpha() and v2_array[i].isalpha():
                if v1_array[i].lower() > v2_array[i].lower():
                    return 1
                if v1_array[i].lower() < v2_array[i].lower():
                    return -1

            else:
                # They are not the same type, and we're comparing mixed letters and numbers.
                # We'll treat letters as less than numbers.
                # This will result in things like rc1, dev9, b2 getting treated like pre-releases
                # as in https://peps.python.org/pep-0440/
                # So 1.2.pre4 would be less than 1.2.1 and (so would 1.2.post1)
                if v1_array[i].isalnum() and v2_array[i].isnumeric():
                    return -1
                elif v1_array[i].isnumeric() and v2_array[i].isalnum():
                    return 1

                # They're both of type letter567 and we'll convert them to be letter.567 and
                # run them through the compare function again
                # We will be dictionary comparing so that 4.alpha4 < 4.beta1
                # but this also means .dev3 < .rc4 (because d is before r)
                # which may make less sense depending on the project.
                letter_number = re.compile("^[a-zA-Z]+[0-9]+$")
                if re.match(letter_number, v1_array[i]) and re.match(
                    letter_number, v2_array[i]
                ):
                    v1_letter_number = re.sub(
                        "([a-zA-Z]+)([0-9]+)", r"\1.\2", v1_array[i]
                    )
                    v2_letter_number = re.sub(
                        "([a-zA-Z]+)([0-9]+)", r"\1.\2", v2_array[i]
                    )
                    return version_compare(v1_letter_number, v2_letter_number)

                # And if all else fails, just compare the strings
                if v1_array[i] > v2_array[i]:
                    return 1
                if v1_array[i] < v2_array[i]:
                    return -1

        else:
            # v1 has more digits than v2
            # Check to see if v1's something that looks like a pre-release (a2, dev8, rc4)
            # e.g. 4.5.a1 would be less than 4.5
            if re.match("([a-zA-Z]+)([0-9]+)", v1_array[i]):
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

        # if what's in v2 next looks like a pre-release number (e.g. a2, dev8, rc4) then we'll
        # claim v1 is still bigger, otherwise we'll say v2 is.
        if re.match("([0-9]+)([a-zA-Z]+)", v2_array[len(v1_array)]):
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
        return f"Version: {self}"
