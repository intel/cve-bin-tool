# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for sqlite

References:
SQLLite version/sha1 data from https://www.sqlite.org/changes.html

CVE list: https://www.cvedetails.com/vulnerability-list/vendor_id-9237/product_id-16355/Sqlite-Sqlite.html

"""
import re
import urllib.error as error
import urllib.request as request

from cve_bin_tool.checkers import Checker
from cve_bin_tool.log import LOGGER
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
    try:
        response = request.urlopen(changeurl)
        lines = response.readlines()

        last_version = "UNKNOWN"
        for line_encoded in lines:
            line = line_encoded.decode("UTF-8")

            ver_match = version_pattern.search(line)
            if ver_match:
                last_version = ver_match.group(1)
            for id_pattern in id_patterns:
                id_match = id_pattern.search(line)
                if id_match:
                    version_map.append([last_version, id_match.group(1)])
                    break

    except error.URLError as err:
        LOGGER.error("Could not fetch " + changeurl + ", " + str(err))

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
        r"sqlite(\d+)\.debug",
    ]  # patterns like the second one aren't ideal (check the end of the file)
    FILENAME_PATTERNS = [r"sqlite", r"sqlite3"]

    mapdb = VersionSignatureDb("sqlite", get_version_map, 30)
    with mapdb:
        VERSION_MAP = mapdb.get_mapping_data()

    def guess_contains(self, lines):
        """Tries to determine if a file includes sqlite"""
        # since the version strings are super unique here, we can guess the version
        # at the same time

        for line in lines:
            for mapping in self.VERSION_MAP:
                if mapping[1] in line:
                    return True

        # If that fails, find a signature that might indicate presence of sqlite
        return super().guess_contains(lines)

    def get_version(self, lines, filename):
        """returns version information for sqlite as found in a given file.

        The most correct way to do this is to search for the sha1 sums per release.
        Fedora rpms have a simpler SQLite version string.
        If neither of those work, try to at least guess the major version
        """

        version_info = super().get_version(lines, filename)

        for line in lines:
            for mapping in self.VERSION_MAP:
                if mapping[1] in line:
                    # overwrite version with the version found by sha mapping
                    version_info["version"] = mapping[0]

        return version_info


"""
Using filenames (containing patterns like '.so' etc.) in the binaries as VERSION_PATTERNS aren't ideal.
The reason behind this is that these might depend on who packages the file (like it 
might work on fedora but not on ubuntu)
"""
