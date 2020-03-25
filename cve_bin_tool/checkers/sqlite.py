#!/usr/bin/python3

"""
CVE checker for sqlite

References:
SQLLite version/sha1 data from https://www.sqlite.org/changes.html

CVE list: https://www.cvedetails.com/vulnerability-list/vendor_id-9237/product_id-16355/Sqlite-Sqlite.html

"""
try:
    import urllib.request as request
    import urllib.error as error
except ImportError:
    import urllib as request
    import urllib as error
import re
from cve_bin_tool.VersionSignature import VersionSignatureDb
from ..util import regex_find
from ..log import LOGGER


def guess_version(lines, version_map):
    """Guesses the sqlite version from the file contents.

    The most correct way to do this is to search for the sha1 sums per release.
    Fedora rpms have a simpler SQLite version string.
    If neither of those work, try to at least guess the major version
    """
    rpm_pattern = re.compile(r"Id: SQLite version (\d+\.\d+\.\d+)")
    vague_pattern = [r"sqlite(\d+)\.debug"]

    for line in lines:
        match = rpm_pattern.search(line)
        if match:
            return match.group(1)

        for mapping in version_map:
            if mapping[1] in line:
                return mapping[0]

    # if all else fails, use the vague pattern
    version = regex_find(lines, *vague_pattern)
    if version:
        if len(version) == 1:
            return "{}.UNKNOWN".format(version)

    return "UNKNOWN"


def guess_contains(lines, version_map):
    """Tries to determine if a file includes sqlite
    """
    # since the version strings are super unique here, we can guess the version
    # at the same time
    for line in lines:
        for mapping in version_map:
            if mapping[1] in line:
                return mapping[0]

    # If that fails, find a signature that might indicate presence of sqlite
    signatures = [
        "unable to open a temporary database file for storing temporary tables",
        "json_object() requires an even number of arguments",
        "ESCAPE expression must be a single character",
        "SQLite version %s",
    ]
    for line in lines:
        for signature in signatures:
            if signature in line:
                return 1

    return 0


def get_version(lines, filename):
    """returns version information for sqlite as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    VPkg: sqlite, sqlite
    """
    mapdb = VersionSignatureDb("sqlite", get_version_map, 30)
    with mapdb:
        mapping = mapdb.get_mapping_data()
    version_info = dict()
    if "sqlite" in filename or "sqlite3" in filename:
        version_info["is_or_contains"] = "is"
        version_info["version"] = guess_version(lines, mapping)

    else:
        version = guess_contains(lines, mapping)
        if version:
            version_info["is_or_contains"] = "contains"
            version_info["version"] = version

    if "is_or_contains" in version_info:
        version_info["modulename"] = "sqlite"

    return version_info


def get_version_map():
    """ Read changelog and get SQLITE_SOURCE_ID to use for versions """
    version_map = []

    changeurl = "https://www.sqlite.org/changes.html"
    try:
        response = request.urlopen(changeurl)
    except error.URLError as err:
        LOGGER.error("Could not fetch " + changeurl + ", " + err)
    lines = response.readlines()

    version_pattern = re.compile(r"<h3>\d{4}-\d{2}-\d{2} \((\d+\.\d+[.\d]*)\)</h3>")
    id_patterns = [
        re.compile(r'SQLITE_SOURCE_ID: "([^"]+)"'),
        re.compile(r'"*(\d{4}-\d{2}-\d{2} \d+:\d+:\d+ [\w]+)"*'),
    ]

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

    return version_map


if __name__ == "__main__":
    get_version_map()
