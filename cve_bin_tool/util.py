# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

# pylint: disable=too-many-arguments
""" Utility classes for the CVE Binary Tool """
import fnmatch
import os
import sys
from collections import defaultdict
from enum import Enum
from typing import NamedTuple


class OrderedEnum(Enum):
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class Remarks(OrderedEnum):
    NewFound = 1, "1", "NewFound", "n", "N"
    Unexplored = 2, "2", "Unexplored", "u", "U", ""
    Confirmed = 3, "3", "Confirmed", "c", "C"
    Mitigated = 4, "4", "Mitigated", "m", "M"
    Ignored = 5, "5", "Ignored", "i", "I"

    def __new__(cls, value, *aliases):
        obj = object.__new__(cls)
        obj._value_ = value
        for alias in aliases:
            cls._value2member_map_[alias] = obj
        return obj


class CVE(NamedTuple):
    cve_number: str
    severity: str
    remarks: Remarks = Remarks.NewFound
    description: str = ""
    comments: str = ""
    score: float = 0
    cvss_version: int = 0


class ProductInfo(NamedTuple):
    vendor: str
    product: str
    version: str


class CVEData(defaultdict):
    def __missing__(self, key):
        if key == "cves":
            self[key] = []
        elif key == "paths":
            self[key] = set()
        else:
            return NotImplemented
        return self[key]


def regex_find(lines, version_patterns) -> str:
    """Search a set of lines to find a match for the given regex"""
    new_guess = ""

    for line in lines:
        for pattern in version_patterns:
            match = pattern.search(line)
            if match:
                new_guess2 = match.group(1).strip()
                if len(new_guess2) > len(new_guess):
                    new_guess = new_guess2
    if new_guess != "":
        new_guess = new_guess.replace("_", ".")
        return new_guess.replace("-", ".")
    else:
        return "UNKNOWN"


def inpath(binary) -> bool:
    """Check to see if something is available in the path.
    Used to check if dependencies are installed before use."""
    if sys.platform == "win32":
        return any(
            list(
                map(
                    lambda dirname: os.path.isfile(
                        os.path.join(dirname, binary + ".exe")
                    ),
                    os.environ.get("PATH", "").split(";"),
                )
            )
        )
    return any(
        list(
            map(
                lambda dirname: os.path.isfile(os.path.join(dirname, binary)),
                os.environ.get("PATH", "").split(":"),
            )
        )
    )


class DirWalk:
    """
    for filename in DirWalk('*.c').walk(roots):
        do a thing with the c-files in the roots directories
    """

    def __init__(
        self,
        pattern: str = "*",
        folder_include_pattern: str = "*",
        folder_exclude_pattern: str = ".git",
        file_exclude_pattern: str = "",
        yield_files: bool = True,
        yield_folders: bool = False,
    ) -> None:
        """
        Generator for walking the file system and filtering the results.
        """
        self.pattern = pattern
        self.folder_include_pattern = folder_include_pattern
        self.folder_exclude_pattern = folder_exclude_pattern
        self.file_exclude_pattern = file_exclude_pattern
        self.yield_files = yield_files
        self.yield_folders = yield_folders

    def walk(self, roots=None):
        """Walk the directory looking for files matching the pattern"""
        if roots is None:
            roots = []
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root):
                # Filters
                filenames[:] = [
                    filename
                    for filename in filenames
                    if self.pattern_match(os.path.join(dirpath, filename), self.pattern)
                    and not self.pattern_match(
                        os.path.join(dirpath, filename), self.file_exclude_pattern
                    )
                    and not self.pattern_match(
                        os.path.join(dirpath, filename), self.folder_exclude_pattern
                    )
                ]
                dirnames[:] = [
                    dirname
                    for dirname in dirnames
                    if self.pattern_match(
                        os.path.join(dirpath, dirname), self.folder_include_pattern
                    )
                    and not self.pattern_match(
                        os.path.join(dirpath, dirname), self.folder_exclude_pattern
                    )
                ]
                # Yields
                if self.yield_files:
                    for filename in filenames:
                        yield os.path.normpath(os.path.join(dirpath, filename))
                if self.yield_folders:
                    for dirname in dirnames:
                        yield os.path.normpath(os.path.join(dirpath, dirname))

    @staticmethod
    def pattern_match(text: str, patterns: str) -> bool:
        """Match filename patterns"""
        if not patterns:
            return False
        for pattern in patterns.split(";"):
            if fnmatch.fnmatch(text, pattern):
                return True
        return False
