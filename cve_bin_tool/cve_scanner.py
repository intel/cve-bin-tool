# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import sqlite3
import sys
from collections import defaultdict
from logging import Logger
from string import ascii_lowercase
from typing import DefaultDict, Dict, List

from pkg_resources import parse_version
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel

from cve_bin_tool.cvedb import DBNAME, DISK_LOCATION_DEFAULT
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.input_engine import TriageData
from cve_bin_tool.linkify import linkify_cve
from cve_bin_tool.log import LOGGER
from cve_bin_tool.theme import cve_theme
from cve_bin_tool.util import CVE, CVEData, ProductInfo


class CVEScanner:
    """
    This class is for reading CVEs from the database
    """

    products_with_cve: int
    products_without_cve: int
    all_cve_data: DefaultDict[ProductInfo, CVEData]

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

    def get_cves(self, product_info: ProductInfo, triage_data: TriageData):
        """Get CVEs against a specific version of a product.

        Example:
            nvd.get_cves('haxx', 'curl', '7.34.0')
        """
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
        self.cursor.execute(query, [vendor, product_info.product, product_info.version])

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

        # Removing * from vendors that are guessed by the package list parser
        vendor = product_info.vendor.replace("*", "")
        self.cursor.execute(query, [vendor, product_info.product, "*"])

        for cve_range in self.cursor:
            (
                cve_number,
                versionStartIncluding,
                versionStartExcluding,
                versionEndIncluding,
                versionEndExcluding,
            ) = cve_range

            parsed_version = parse_version(product_info.version)

            # pep-440 doesn't include versions of the type 1.1.0g used by openssl
            # so if this is openssl, convert the last letter to a .number
            if product_info.product == "openssl":
                # if last character is a letter, convert it to .number
                # version = self.openssl_convert(product_info.version)
                versionStartIncluding = self.openssl_convert(versionStartIncluding)
                versionStartExcluding = self.openssl_convert(versionStartExcluding)
                versionEndIncluding = self.openssl_convert(versionEndIncluding)
                versionEndExcluding = self.openssl_convert(versionEndExcluding)
                parsed_version = parse_version(
                    self.openssl_convert(product_info.version)
                )

            # check the start range
            passes_start = False
            if (
                versionStartIncluding is not self.RANGE_UNSET
                and parsed_version >= parse_version(versionStartIncluding)
            ):
                passes_start = True
            if (
                versionStartExcluding is not self.RANGE_UNSET
                and parsed_version > parse_version(versionStartExcluding)
            ):
                passes_start = True

            if (
                versionStartIncluding is self.RANGE_UNSET
                and versionStartExcluding is self.RANGE_UNSET
            ):
                # then there is no start range so just say true
                passes_start = True

            # check the end range
            passes_end = False
            if (
                versionEndIncluding is not self.RANGE_UNSET
                and parsed_version <= parse_version(versionEndIncluding)
            ):
                passes_end = True

            if (
                versionEndExcluding is not self.RANGE_UNSET
                and parsed_version < parse_version(versionEndExcluding)
            ):
                passes_end = True
            if (
                versionEndIncluding is self.RANGE_UNSET
                and versionEndExcluding is self.RANGE_UNSET
            ):
                # then there is no end range so it passes
                passes_end = True
            # if it fits into both ends of the range, add the cve number
            if passes_start and passes_end:
                cve_list.append(cve_number)

        # Go through and get all the severities
        if cve_list:
            query = f"""
            SELECT CVE_number, severity, description, score, cvss_version
            FROM cve_severity
            WHERE CVE_number IN ({",".join(["?"] * len(cve_list))}) AND score >= ?
            ORDER BY CVE_number
            """
            # Add score parameter to tuple listing CVEs to pass to query
            cve_list.append(self.score)

            result = self.cursor.execute(query, cve_list)

            cves: List[CVE] = []
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
                self.logger.info(f"Known CVEs in {product_info}")
                # error_mode.value will only be greater than 1 if quiet mode.
                if self.error_mode.value > 1:
                    title = f"[default][b]{len(cves)}[/b] CVE(s) in [b]{product_info.vendor}.{product_info.product}[/b] v[b]{product_info.version}[/b]"
                    self.CONSOLE.log()
                    self.CONSOLE.log(
                        Panel(
                            Columns(
                                (
                                    linkify_cve(
                                        f"[{cve.severity.lower()}]{cve.cve_number}"
                                    )
                                    for cve in cves
                                ),
                                padding=(0, 2),
                            ),
                            padding=1,
                            border_style="red",
                            title=title,
                        )
                    )
                    self.CONSOLE.log()
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
            self.all_cve_data[product_info]["cves"] = [CVE("UNKNOWN", "UNKNOWN")]

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
