# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

""" Utility classes for the CVE Binary Tool """
from __future__ import annotations

import fnmatch
import os
import sys
from enum import Enum
from pathlib import Path
from typing import DefaultDict, Iterator, List, NamedTuple, Pattern, Set, Union


class OrderedEnum(Enum):
    def __ge__(self, other: OrderedEnum) -> bool:
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other: OrderedEnum) -> bool:
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other: OrderedEnum) -> bool:
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other: OrderedEnum) -> bool:
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class Remarks(OrderedEnum):
    NewFound = 1, "1", "NewFound", "n", "N"
    Unexplored = 2, "2", "Unexplored", "u", "U", ""
    Confirmed = 3, "3", "Confirmed", "c", "C"
    Mitigated = 4, "4", "Mitigated", "m", "M"
    Ignored = 5, "5", "Ignored", "i", "I"

    def __new__(cls, value: int, *aliases: str) -> Remarks:
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
    cvss_vector: str = ""
    data_source: str = ""
    last_modified: str = ""
    metric: dict[str, dict[float, str]] = {}


class ProductInfo(NamedTuple):
    vendor: str
    product: str
    version: str


class ScanInfo(NamedTuple):
    product_info: ProductInfo
    file_path: str


class VersionInfo(NamedTuple):
    start_including: str
    start_excluding: str
    end_including: str
    end_excluding: str


class CVEData(DefaultDict[str, Union[List[CVE], Set[str]]]):
    def __missing__(self, key: str) -> list[CVE] | set[str]:
        if key == "cves":
            new_list: list[CVE] = []
            self[key] = new_list
        elif key == "paths":
            new_set: set[str] = set()
            self[key] = new_set
        else:
            return NotImplemented
        return self[key]


def regex_find(
    lines: str, version_patterns: list[Pattern[str]], ignore: list[Pattern[str]]
) -> str:
    """Search a set of lines to find a match for the given regex"""
    new_guess = ""

    for pattern in version_patterns:
        match = pattern.search(lines)
        if match:
            new_guess = match.group(1).strip()
            for i in ignore:
                if str(i) in str(new_guess) or str(new_guess) in str(i):
                    new_guess = ""
            break
    if new_guess != "":
        new_guess = new_guess.replace("_", ".")
        return new_guess.replace("-", ".")
    else:
        return "UNKNOWN"


def inpath(binary: str) -> bool:
    """Check to see if something is available in the path.
    Used to check if dependencies are installed before use."""
    if sys.platform == "win32":
        return any(
            list(
                map(
                    lambda dirname: (Path(dirname) / (binary + ".exe")).is_file(),
                    os.environ.get("PATH", "").split(";"),
                )
            )
        )
    return any(
        list(
            map(
                lambda dirname: (Path(dirname) / binary).is_file(),
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

    def walk(self, roots: list[str] | None = None) -> Iterator[str]:
        """Walk the directory looking for files matching the pattern"""
        if roots is None:
            roots = []
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root):
                # Filters
                filenames[:] = [
                    filename
                    for filename in filenames
                    if self.pattern_match(str(Path(dirpath) / filename), self.pattern)
                    and not self.pattern_match(
                        str(Path(dirpath) / filename), self.file_exclude_pattern
                    )
                    and not self.pattern_match(
                        str(Path(dirpath) / filename), self.folder_exclude_pattern
                    )
                    and not (Path(dirpath) / filename).is_symlink()
                ]
                dirnames[:] = [
                    dirname
                    for dirname in dirnames
                    if self.pattern_match(
                        str(Path(dirpath) / dirname), self.folder_include_pattern
                    )
                    and not self.pattern_match(
                        str(Path(dirpath) / dirname), self.folder_exclude_pattern
                    )
                ]
                # Yields
                if self.yield_files:
                    for filename in filenames:
                        yield str((Path(dirpath) / filename).resolve())
                if self.yield_folders:
                    for dirname in dirnames:
                        yield str((Path(dirpath) / dirname).resolve())

    @staticmethod
    def pattern_match(text: str, patterns: str) -> bool:
        """Match filename patterns"""
        if not patterns:
            return False
        for pattern in patterns.split(";"):
            if fnmatch.fnmatch(text, pattern):
                return True
        return False
