# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import re
import sqlite3
import sys
from collections import defaultdict
from logging import Logger
from string import ascii_lowercase
from typing import DefaultDict, Dict, List, Tuple, Union

from packaging.version import LegacyVersion, Version
from packaging.version import parse as parse_version
from rich.console import Console

from cve_bin_tool.cvedb import DBNAME, DISK_LOCATION_DEFAULT
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.input_engine import TriageData
from cve_bin_tool.log import LOGGER
from cve_bin_tool.theme import cve_theme
from cve_bin_tool.util import CVE, CVEData, ProductInfo, VersionInfo


class CVEScanner:
    """
    This class is for reading CVEs from the database
    """

    products_with_cve: int
    products_without_cve: int
    all_cve_data: DefaultDict[ProductInfo, CVEData]
    all_cve_version_info: Dict[str, VersionInfo]

    RANGE_UNSET: str = ""
    dbname: str = os.path.join(DISK_LOCATION_DEFAULT, DBNAME)
    CONSOLE: Console = Console(file=sys.stderr, theme=cve_theme)
    ALPHA_TO_NUM: Dict[str, int] = dict(zip(ascii_lowercase, range(26)))

    def __init__(
        self,
        score: int = 0,
        logger: Logger = None,
        error_mode: ErrorMode = ErrorMode.TruncTrace,
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.error_mode = error_mode
        self.score = score
        self.products_with_cve = 0
        self.products_without_cve = 0
        self.all_cve_data = defaultdict(CVEData)
        self.all_cve_version_info = dict()

    def get_cves(self, product_info: ProductInfo, triage_data: TriageData):
        """Get CVEs against a specific version of a product.

        Example:
            nvd.get_cves('haxx', 'curl', '7.34.0')
        """
        if product_info.vendor == "UNKNOWN":
            return

        if product_info in self.all_cve_data:
            # If product_info already in all_cve_data no need to fetch cves from database again
            # We just need to update paths.
            self.products_with_cve += 1
            self.all_cve_data[product_info]["paths"] |= triage_data["paths"]
            return

        # Check for anything directly marked
        query = """
        SELECT CVE_number FROM cve_range
        WHERE vendor=? AND product=? AND version=?
        """
        # Removing * from vendors that are guessed by the package list parser
        vendor = product_info.vendor.replace("*", "")

        # Need to manipulate version to ensure canonical form of version

        parsed_version, parsed_version_between = self.canonical_convert(product_info)

        self.cursor.execute(query, [vendor, product_info.product, str(parsed_version)])

        cve_list = list(map(lambda x: x[0], self.cursor.fetchall()))

        # Check for any ranges
        query = """
        SELECT
            CVE_number,
            versionStartIncluding,
            versionStartExcluding,
            versionEndIncluding,
            versionEndExcluding
        FROM cve_range
        WHERE vendor=? AND product=? AND version=?
        """

        self.cursor.execute(query, [vendor, product_info.product, "*"])

        for cve_range in self.cursor:
            (
                cve_number,
                version_start_including,
                version_start_excluding,
                version_end_including,
                version_end_excluding,
            ) = cve_range

            # pep-440 doesn't include versions of the type 1.1.0g used by openssl
            # so if this is openssl, convert the last letter to a .number
            if product_info.product == "openssl":
                # if last character is a letter, convert it to .number
                # version = self.openssl_convert(product_info.version)
                version_start_including = self.openssl_convert(version_start_including)
                version_start_excluding = self.openssl_convert(version_start_excluding)
                version_end_including = self.openssl_convert(version_end_including)
                version_end_excluding = self.openssl_convert(version_end_excluding)
                parsed_version = parsed_version_between

            # check the start range
            passes_start = False
            if (
                version_start_including is not self.RANGE_UNSET
                and parsed_version >= parse_version(version_start_including)
            ):
                passes_start = True

            if (
                version_start_excluding is not self.RANGE_UNSET
                and parsed_version > parse_version(version_start_excluding)
            ):
                passes_start = True

            if (
                version_start_including is self.RANGE_UNSET
                and version_start_excluding is self.RANGE_UNSET
            ):
                # then there is no start range so just say true
                passes_start = True

            # check the end range
            passes_end = False
            if (
                version_end_including is not self.RANGE_UNSET
                and parsed_version <= parse_version(version_end_including)
            ):
                passes_end = True

            if (
                version_end_excluding is not self.RANGE_UNSET
                and parsed_version < parse_version(version_end_excluding)
            ):
                passes_end = True

            if (
                version_end_including is self.RANGE_UNSET
                and version_end_excluding is self.RANGE_UNSET
            ):
                # then there is no end range so it passes
                passes_end = True
            # if it fits into both ends of the range, add the cve number
            if passes_start and passes_end:
                cve_list.append(cve_number)
                self.all_cve_version_info[cve_number] = VersionInfo(
                    start_including=version_start_including,
                    start_excluding=version_start_excluding,
                    end_including=version_end_including,
                    end_excluding=version_end_excluding,
                )

        # Go through and get all the severities
        if cve_list:

            cves: List[CVE] = []
            finished = False
            max_cves = 500
            remaining = len(cve_list)
            start = 0

            while not finished:
                # Limit number of CVEs in single query to maximum
                number_of_cves = min(remaining, max_cves)
                end = start + number_of_cves
                remaining = remaining - number_of_cves
                finished = remaining == 0

                query = f"""
                SELECT CVE_number, severity, description, score, cvss_version, cvss_vector
                FROM cve_severity
                WHERE CVE_number IN ({",".join(["?"] * number_of_cves)}) AND score >= ?
                ORDER BY CVE_number
                """
                # Add score parameter to tuple listing CVEs to pass to query
                result = self.cursor.execute(query, cve_list[start:end] + [self.score])
                start = end

                for row in result:
                    triage = triage_data.get(row["cve_number"]) or triage_data.get(
                        "default"
                    )
                    # Only scan cves if triage is not None.
                    # Triage will only be None if triage_data don't have default attribute.
                    # NOTE: Triage can be empty dictionary so checking `if triage:` won't suffice.
                    if triage is not None:
                        row_dict = dict(row)
                        row_dict.update(triage)
                        # print(row_dict)
                        row_dict["severity"] = row_dict["severity"] or row["severity"]
                        row_dict["score"] = row_dict["score"] or row["score"]
                        row_dict["cvss_version"] = (
                            row_dict["cvss_version"] or row["cvss_version"]
                        )
                        cve = CVE(**row_dict)
                        cves.append(cve)

            if cves:
                self.products_with_cve += 1
                self.logger.debug(f"Known CVEs in {product_info}")

                # error_mode.value will only be greater than 1 if quiet mode.
                if self.error_mode.value > 1:
                    self.logger.info(
                        f"{len(cves)} CVE(s) in {product_info.vendor}.{product_info.product} v{product_info.version}"
                    )
            else:
                # No cves found for (product, vendor, version) tuple in the NVD database.
                self.products_without_cve += 1

            self.all_cve_data[product_info]["cves"] = cves
            self.all_cve_data[product_info]["paths"] |= triage_data["paths"]

        else:
            # There isn't any entry for (product, vendor, version) tuple in the NVD database.
            self.products_without_cve += 1
            self.logger.debug(
                f"No CVEs found for {product_info}. Is the vendor/product info correct?"
            )

    def openssl_convert(self, version: str) -> str:
        """pkg_resources follows pep-440 which doesn't expect openssl style 1.1.0g version numbering
        So to fake it, if the last character is a letter, replace it with .number before comparing"""
        if not version:  # if version is empty return it.
            return version

        last_char = version[-1]
        second_last_char = version[-2]

        if last_char in self.ALPHA_TO_NUM and second_last_char in self.ALPHA_TO_NUM:
            version = f"{version[:-2]}.{self.ALPHA_TO_NUM[second_last_char]}.{self.ALPHA_TO_NUM[last_char]}"

        elif last_char in self.ALPHA_TO_NUM:
            version = f"{version[:-1]}.{self.ALPHA_TO_NUM[last_char]}"
        return version

    VersionType = Union[Version, LegacyVersion]

    def canonical_convert(
        self, product_info: ProductInfo
    ) -> Tuple[VersionType, VersionType]:
        version_between = parse_version("")
        if product_info.version == "":
            return parse_version(product_info.version), version_between
        if product_info.product == "openssl":
            pv = re.search(r"\d[.\d]*[a-z]?", product_info.version)
            version_between = parse_version(self.openssl_convert(pv.group(0)))
        else:
            # Ensure canonical form of version numbering
            if ":" in product_info.version:
                # Handle x:a.b<string> e.g. 2:7.4+23
                components = product_info.version.split(":")
                pv = re.search(r"\d[.\d]*", components[1])
            else:
                # Handle a.b.c<string> e.g. 1.20.9rel1
                pv = re.search(r"\d[.\d]*", product_info.version)
        parsed_version = parse_version(pv.group(0))
        return parsed_version, version_between

    def affected(self):
        """Returns list of product name and version tuples identified from
        scan"""
        return sorted(
            (cve_data.product, cve_data.version) for cve_data in self.all_cve_data
        )

    def __enter__(self):
        self.connection = sqlite3.connect(self.dbname)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cursor.close()
        self.connection.close()
