# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import sqlite3
import sys
from collections import defaultdict
from logging import Logger
from pathlib import Path
from string import ascii_lowercase
from typing import DefaultDict, Dict, List

from rich.console import Console

from cve_bin_tool.cvedb import DBNAME, DISK_LOCATION_DEFAULT
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.input_engine import TriageData
from cve_bin_tool.log import LOGGER
from cve_bin_tool.theme import cve_theme
from cve_bin_tool.util import CVE, CVEData, ProductInfo, Remarks, VersionInfo
from cve_bin_tool.version_compare import Version


class CVEScanner:
    """
    This class is for reading CVEs from the database
    """

    products_with_cve: int
    products_without_cve: int
    all_cve_data: DefaultDict[ProductInfo, CVEData]
    all_cve_version_info: Dict[str, VersionInfo]

    RANGE_UNSET: str = ""
    dbname: str = str(Path(DISK_LOCATION_DEFAULT) / DBNAME)
    CONSOLE: Console = Console(file=sys.stderr, theme=cve_theme)
    ALPHA_TO_NUM: Dict[str, int] = dict(zip(ascii_lowercase, range(26)))

    def __init__(
        self,
        score: int = 0,
        check_metrics: bool = False,
        epss_percentile: float = 0.0,
        epss_probability: float = 0.0,
        logger: Logger = None,
        error_mode: ErrorMode = ErrorMode.TruncTrace,
        check_exploits: bool = False,
        exploits_list: List[str] = [],
        disabled_sources: List[str] = [],
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.error_mode = error_mode
        self.score = score
        self.check_metrics = check_metrics
        self.epss_percentile = epss_percentile
        self.epss_probability = epss_probability
        self.products_with_cve = 0
        self.products_without_cve = 0
        self.all_cve_data = defaultdict(CVEData)
        self.all_cve_version_info = dict()
        self.check_exploits = check_exploits
        self.exploits_list = exploits_list
        self.disabled_sources = disabled_sources
        self.all_product_data = dict()

    def get_cves(self, product_info: ProductInfo, triage_data: TriageData):
        """Get CVEs against a specific version of a product.
        Example:
            nvd.get_cves('haxx', 'curl', '7.34.0')
        """

        # Prevent any queries resulting in CVEs with UNKNOWN score value
        # being reported
        if self.score > 10 or self.epss_probability > 1.0 or self.epss_percentile > 1.0:
            return

        if product_info.vendor == "UNKNOWN":
            # Add product
            if product_info not in self.all_product_data:
                self.logger.debug(f"Add product {product_info}")
                # Number of CVEs is 0
                self.all_product_data[product_info] = 0
            return

        if product_info in self.all_cve_data:
            # If product_info already in all_cve_data, no need to fetch CVEs from the database again.
            # We just need to update paths and triage data.
            self.logger.debug(
                f"{product_info} already processed. Update paths {triage_data['paths']}"
            )

            # Update the triage data
            cve_data = self.all_cve_data[product_info]["cves"]
            new_cve_data = []

            for cve in cve_data:
                cve_number = cve.cve_number
                if cve_number in triage_data:
                    for key in [
                        "remarks",
                        "comments",
                        "response",
                        "justification",
                        "severity",
                    ]:
                        data = triage_data[cve_number].get(key)
                        if data:
                            if (
                                key == "severity"
                                and self.check_exploits
                                and cve_number in self.exploits_list
                            ):
                                data += "-EXPLOIT"

                            self.logger.debug(f"Setting field {key} to: {data}")
                            cve = cve._replace(**{key: data})
                new_cve_data.append(cve)

            self.all_cve_data[product_info]["cves"] = new_cve_data

            # Update paths
            self.all_cve_data[product_info]["paths"] |= set(triage_data["paths"])
            return

        # Check for anything directly marked
        query = """
        SELECT CVE_number FROM cve_range
        WHERE vendor=? AND product=? AND version=?
        """
        # Removing * from vendors that are guessed by the package list parser
        vendor = product_info.vendor.replace("*", "")

        # Use our Version class to do version compares
        parsed_version = Version(product_info.version)

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

            # check the start range
            passes_start = False
            if (
                version_start_including is not self.RANGE_UNSET
                and parsed_version >= Version(version_start_including)
            ):
                passes_start = True

            if (
                version_start_excluding is not self.RANGE_UNSET
                and parsed_version > Version(version_start_excluding)
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
                and parsed_version <= Version(version_end_including)
            ):
                passes_end = True

            if (
                version_end_excluding is not self.RANGE_UNSET
                and parsed_version < Version(version_end_excluding)
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

        product_info_data: CVEData | None = self.all_cve_data.get(product_info)
        prev_cves: List[CVE] = (
            product_info_data.get("cves", []) if product_info_data is not None else []  # type: ignore
        )
        cves: List[CVE] = []

        # Go through and get all the severities
        if cve_list:
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
                SELECT CVE_number, severity, description, score, cvss_version, cvss_vector, data_source
                FROM cve_severity
                WHERE CVE_number IN ({",".join(["?"] * number_of_cves)}) AND score >= ? and description != "unknown"
                ORDER BY CVE_number, last_modified DESC
                """  # nosec
                # Add score parameter to tuple listing CVEs to pass to query
                result = self.cursor.execute(query, cve_list[start:end] + [self.score])
                start = end

                for row in result:
                    # Skipping CVEs from disabled data sources
                    if row["data_source"] in self.disabled_sources:
                        continue

                    # To avoid duplicate reporting, skip reporting CVE if already reported
                    duplicate_found = False
                    for c in cves:
                        if c.cve_number == row["cve_number"]:
                            self.logger.debug(
                                f"{row['cve_number']} already reported from {c.data_source}"
                            )
                            duplicate_found = True
                            break

                    if duplicate_found:
                        continue

                    # Check if we already found this CVE with a previous scan.
                    # In that case we need to check where to get our triage info
                    # from.
                    # TODO: turn the list of CVEs into a set to avoid needing
                    # the linear-time lookup.
                    prev_cve = next(
                        (
                            cve
                            for cve in prev_cves
                            if cve.cve_number == row["cve_number"]
                        ),
                        None,
                    )

                    triage = triage_data.get(row["cve_number"]) or triage_data.get(
                        "default"
                    )
                    if prev_cve is None:
                        row_dict = dict(row)

                        # print(row_dict)
                        row_dict["severity"] = row_dict["severity"] or row["severity"]
                        # Checking for exploits
                        if (
                            self.check_exploits
                            and row_dict["cve_number"] in self.exploits_list
                        ):
                            row_dict["severity"] += "-EXPLOIT"
                        row_dict["score"] = row_dict["score"] or row["score"]
                        row_dict["cvss_version"] = (
                            row_dict["cvss_version"] or row["cvss_version"]
                        )
                        # executing query to get metric for CVE
                        if self.check_metrics:
                            metric_result = self.metric(
                                (row["cve_number"],),
                                self.epss_percentile,
                                self.epss_probability,
                            )
                            # row_dict doesnt have metric as key. As it based on result from query on
                            # cve_severity table declaring row_dict[metric]
                            row_dict["metric"] = {}
                            # looping for result of query for metrics.
                            for key, value in metric_result.items():
                                row_dict["metric"][key] = [
                                    value[0],
                                    value[1],
                                ]
                            # checking if epss percentile filter is applied
                            if (
                                self.epss_percentile > 0.0
                                or self.epss_probability > 0.0
                            ):
                                # if epss filter is applied and condition is failed to satisfy
                                # row_dict["metric"] will be empty
                                if not row_dict["metric"]:
                                    # continue to not include that particular cve
                                    continue
                            self.logger.debug(
                                f'metrics found in CVE {row_dict["cve_number"]}  is {row_dict["metric"]}'
                            )
                        cve = CVE(**row_dict)
                    else:
                        cve = prev_cve

                    # We assume that only one source has the triage info.
                    # We try to figure out here which one.
                    # If we have useful info in the triage data we received,
                    # then we use it.
                    if triage is not None and (
                        # Either the new cve does not have triage data,
                        # or it is trivial (newly found cve)
                        not cve.remarks
                        or cve.remarks == Remarks.NewFound
                    ):
                        for key in [
                            "remarks",
                            "comments",
                            "response",
                            "justification",
                            "severity",
                        ]:
                            data = triage.get(key)
                            if data:
                                if (
                                    key == "severity"
                                    and self.check_exploits
                                    and row_dict["cve_number"] in self.exploits_list
                                ):
                                    data += "-EXPLOIT"

                                self.logger.debug(f"Setting field {key} to: {data}")
                                cve = cve._replace(**{key: data})

                    cves.append(cve)

            if cves:
                self.products_with_cve += 1
                self.logger.debug(f"Known CVEs in {product_info}")

                # error_mode.value will only be greater than 1 if quiet mode.
                if self.error_mode.value > 1:
                    self.logger.info(
                        f"{len(cves)} CVE(s) in {product_info.vendor}.{product_info.product} version {product_info.version}"
                    )
                self.all_cve_data[product_info]["cves"] = cves
                self.all_cve_data[product_info]["paths"] |= set(triage_data["paths"])
            else:
                # No cves found for (product, vendor, version) tuple in the NVD database.
                self.products_without_cve += 1
                self.logger.debug(f"No CVEs for {product_info}")

        else:
            # There isn't any entry for (product, vendor, version) tuple in the NVD database.
            self.products_without_cve += 1
            self.logger.debug(
                f"No CVEs found for {product_info}. Is the vendor/product info correct?"
            )

        if product_info not in self.all_product_data:
            self.all_product_data[product_info] = len(cves)

    def filter_triage_data(self):
        """
        Filter out triage data that is not relevant to the CVEs found,
        specifically those marked as NotAffected or FalsePositives.
        """
        to_delete: List[ProductInfo] = []

        for product_info, cve_data in self.all_cve_data.items():
            original_cves = cve_data["cves"]
            filtered_cves = []
            filtered_out_cves = []

            for cve in original_cves:
                if cve.remarks not in {Remarks.NotAffected, Remarks.FalsePositive}:
                    filtered_cves.append(cve)
                else:
                    filtered_out_cves.append(cve)

            for cve in filtered_out_cves:
                self.logger.info(
                    f"Filtered CVE: {cve.cve_number} for Product: {product_info.product}"
                )

            if filtered_cves:
                cve_data["cves"] = filtered_cves
                self.logger.debug(
                    f"Filtered triage data for {product_info.product}: {[cve.cve_number for cve in filtered_cves]}"
                )
            else:
                to_delete.append(product_info)

        for product_info in to_delete:
            del self.all_cve_data[product_info]
            self.logger.debug(
                f"Removed product info for {product_info.product} due to no relevant CVEs"
            )

    def affected(self):
        """Returns list of vendor.product and version tuples identified from
        scan"""
        return sorted(
            (cve_data.vendor + "." + cve_data.product, cve_data.version)
            for cve_data in self.all_cve_data
        )

    def metric(self, cve_number, epss_percentile, epss_probability):
        """The query needs to be executed separately because if it is executed using the same cursor, the search stops.
        We need to create a separate connection and cursor for the query to be executed independently.
        Finally, the function should return a dictionary with the metrics of a given CVE.
        """
        conn = sqlite3.connect(self.dbname)
        cur = conn.cursor()
        query = """
                SELECT metrics.metrics_name, cve_metrics.metric_score, cve_metrics.metric_field
                FROM cve_metrics, metrics
                WHERE cve_metrics.cve_number = ? AND cve_metrics.metric_id = metrics.metrics_id
                GROUP BY cve_metrics.metric_id;
                """
        metric_result = cur.execute(query, (cve_number))
        met = {}
        # looping for result of query for metrics.
        for result in metric_result:
            metric_name, metric_score, metric_field = result
            # if metric is EPSS if metric field must represent EPSS percentile
            if metric_name == "EPSS":
                # comparing if EPSS percentile found in CVE is less then EPSS percentile return

                # checks if both epss percentile and epss probaility are given. And if given they are greater than found in current CVE. if not it break loops and skips that CVE
                if (
                    epss_probability
                    and epss_percentile
                    and (
                        float(metric_field) < float(epss_percentile)
                        or float(metric_score) < float(epss_probability)
                    )
                ):
                    break
                # checks if only epss percentile is given and if given then it should be higher than found epss percentile in current CVE. if not it break loops and skips that CVE
                elif epss_percentile and float(metric_field) < epss_percentile:
                    break
                # checks if only epss probability is given and if given then it should be higher than found epss probability in current CVE. if not it break loops and skips that CVE
                elif epss_probability and float(metric_score) < epss_probability:
                    break

            self.logger.debug(f"metrics found in CVE {cve_number}  is {met}")
            met[metric_name] = [
                metric_score,
                metric_field,
            ]
        cur.close()
        conn.close()
        return met

    def __enter__(self):
        self.connection = sqlite3.connect(self.dbname)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cursor.close()
        self.connection.close()
