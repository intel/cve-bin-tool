# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for sqlite

References:
SQLLite version/sha1 data from https://www.sqlite.org/changes.html

CVE list: https://www.cvedetails.com/vulnerability-list/vendor_id-9237/product_id-16355/Sqlite-Sqlite.html

"""
import re

from cve_bin_tool.checkers import Checker
from cve_bin_tool.util import make_http_requests
from cve_bin_tool.version_signature import VersionSignatureDb


def get_version_map():
    """Read changelog and get SQLITE_SOURCE_ID to use for versions"""
    version_map = []

    changeurl = "https://www.sqlite.org/changes.html"
    version_pattern = re.compile(r"<h3>\d{4}-\d{2}-\d{2} \((\d+\.\d+[.\d]*)\)</h3>")
    id_patterns = [
        re.compile(r'SQLITE_SOURCE_ID: "([^"]+)"'),
        re.compile(r'"*(\d{4}-\d{2}-\d{2} \d+:\d+:\d+ [\w]+)"*'),
    ]

    # timeout = 300s = 5minutes. This is a guess.
    response = make_http_requests("text", url=changeurl, timeout=300)
    lines = response.splitlines()

    last_version = "UNKNOWN"
    for line in lines:
        ver_match = version_pattern.search(line)
        if ver_match:
            last_version = ver_match.group(1)
        for id_pattern in id_patterns:
            id_match = id_pattern.search(line)
            if id_match:
                version_map.append([last_version, id_match.group(1)])
                break

    return version_map


class SqliteChecker(Checker):
    CONTAINS_PATTERNS = [
        r"unable to open a temporary database file for storing temporary tables",
        r"json_object() requires an even number of arguments",
        r"ESCAPE expression must be a single character",
        r"SQLite version %s",
    ]
    VENDOR_PRODUCT = [("sqlite", "sqlite")]
    VERSION_PATTERNS = [
        r"Id: SQLite version (\d+\.\d+\.\d+)",
        r"(\d{4}-\d{2}-\d{2} \d+:\d+:\d+ [\w]+)[a-z\r\n]*(?:SQLite|SQLITE|DESC)",
    ]
    FILENAME_PATTERNS = [r"sqlite", r"sqlite3"]

    mapdb = VersionSignatureDb("sqlite", get_version_map, 30)
    with mapdb:
        VERSION_MAP = mapdb.get_mapping_data()

    def guess_contains(self, lines):
        """Tries to determine if a file includes sqlite"""
        # since the version strings are super unique here, we can guess the version
        # at the same time

        for mapping in self.VERSION_MAP:
            # Truncate last four characters as "If the source code has been edited
            # in any way since it was last checked in, then the last four
            # hexadecimal digits of the hash may be modified."
            # https://www.sqlite.org/c3ref/c_source_id.html
            if mapping[1][:-4] in lines:
                return True

        # If that fails, find a signature that might indicate presence of sqlite
        return super().guess_contains(lines)

    def get_version(self, lines, filename):
        """returns version information for sqlite as found in a given file.

        The most correct way to do this is to search for the sha1 sums per release.
        Fedora rpms have a simpler SQLite version string.
        """

        version_info = super().get_version(lines, filename)

        for mapping in self.VERSION_MAP:
            # Truncate last four characters as "If the source code has been edited
            # in any way since it was last checked in, then the last four
            # hexadecimal digits of the hash may be modified."
            # https://www.sqlite.org/c3ref/c_source_id.html
            if mapping[1][:-4] in lines:
                # overwrite version with the version found by sha mapping
                version_info["version"] = mapping[0]

        return version_info
