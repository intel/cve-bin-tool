# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from logging import Logger
from pathlib import Path

from cve_bin_tool.cve_scanner import CVEScanner

from .cvedb import DISK_LOCATION_DEFAULT
from .error_handler import (
    ErrorHandler,
    ErrorMode,
    InvalidIntermediateJsonError,
    InvalidJsonError,
)
from .input_engine import TriageData
from .log import LOGGER
from .util import DirWalk, ProductInfo, Remarks

REQUIRED_INTERMEDIATE_METADATA = {
    "scanned_dir",
    "total_files",
    "products_without_cve",
    "products_with_cve",
    "tag",
    "timestamp",
}


class MergeReports:
    def __init__(
        self,
        merge_files: list[str],
        logger: Logger | None = None,
        error_mode=ErrorMode.TruncTrace,
        cache_dir=DISK_LOCATION_DEFAULT,
        score=0,
        filter_tag=[],
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.merge_files = merge_files
        self.intermediate_cve_data = []
        self.all_cve_data = []
        self.file_stack = []
        self.error_mode = error_mode
        self.total_inter_files = 0
        self.total_files = 0
        self.products_with_cve = 0
        self.products_without_cve = 0
        self.cache_dir = cache_dir
        self.merged_files = ["tag"]
        self.score = score
        self.filter_tag = filter_tag

        self.walker = DirWalk(
            pattern=";".join(
                file_path if file_path.endswith(".json") else file_path + "*.json"
                for file_path in self.merge_files
            ),
            yield_files=True,
        ).walk

    def recursive_scan(self, merge_files):
        """Recursive scan all json in a directory/regex path"""
        for intermediate_path in merge_files:
            intermediate_path = Path(intermediate_path)
            if intermediate_path.is_dir():
                for filepath in self.walker([intermediate_path]):
                    self.file_stack.append(filepath)
                    yield filepath
                    self.file_stack.pop()
            elif intermediate_path.is_file() and not intermediate_path.is_symlink():
                self.file_stack.append(intermediate_path)
                yield intermediate_path
                self.file_stack.pop()

    def scan_intermediate_file(self, filename):
        """Reads intermediate json file through filename and verify missing fields"""
        self.logger.debug(f"Loading file: {filename}")

        with open(filename) as json_file:
            filename = Path(filename)
            json_file = json_file.read()
            inter_data = json.loads(json_file)
            if not inter_data or not isinstance(inter_data, dict):
                with ErrorHandler(mode=self.error_mode):
                    raise InvalidJsonError(filename)

            required_fields = set({"metadata", "report"})
            missing_fields = required_fields - set(inter_data.keys())

            if missing_fields == set():
                if isinstance(inter_data["metadata"], dict):
                    missing_fields = set(REQUIRED_INTERMEDIATE_METADATA) - set(
                        inter_data["metadata"].keys()
                    )
                    if missing_fields == set():
                        if isinstance(inter_data["report"], list):
                            self.logger.debug(
                                f"Adding data from {filename.name} with timestamp {inter_data['metadata']['timestamp']}"
                            )
                            inter_data["metadata"]["severity"] = get_severity_count(
                                inter_data["report"]
                            )
                            return inter_data

            if missing_fields != set():
                self.logger.debug(f"{missing_fields} are required fields")
                return None

            with ErrorHandler(mode=self.error_mode):
                raise InvalidIntermediateJsonError(filename)

    def merge_intermediate(self):
        """Merge valid intermediate dictionaries"""

        for inter_file in self.recursive_scan(self.merge_files):
            # Create a list of intermediate files dictionary
            intermediate_data = self.scan_intermediate_file(inter_file)
            if intermediate_data is None:
                return

            if (
                self.filter_tag == []
                or intermediate_data["metadata"]["tag"] in self.filter_tag
            ):
                self.intermediate_cve_data.append(intermediate_data)
                self.total_inter_files += 1

        if self.intermediate_cve_data:
            # sort on basis of timestamp and scans
            self.intermediate_cve_data.sort(
                reverse=True,
                key=lambda inter: datetime.strptime(
                    inter["metadata"]["timestamp"], "%Y-%m-%d.%H-%M-%S"
                ),
            )
            self.all_cve_data = self.remove_intermediate_duplicates()
            merged_cve_scanner = self.get_intermediate_cve_scanner(
                [self.all_cve_data], self.score
            )[0]
            merged_cve_scanner.products_with_cve = self.products_with_cve
            merged_cve_scanner.products_without_cve = self.products_without_cve

            return merged_cve_scanner

        self.logger.error("No valid Intermediate reports found!")
        return {}

    def remove_intermediate_duplicates(self) -> list[dict[str, str]]:
        """Returns a list of dictionary with same format as cve-bin-tool json output"""

        output = {}
        for inter_data in self.intermediate_cve_data:
            self.products_with_cve += int(inter_data["metadata"]["products_with_cve"])
            self.products_without_cve += int(
                inter_data["metadata"]["products_without_cve"]
            )
            for cve in inter_data["report"]:
                if cve["cve_number"] != "UNKNOWN":
                    if cve["cve_number"] not in output:
                        output[cve["cve_number"]] = cve
                        self.total_files += len(cve["paths"].split(","))
                    else:
                        path_list = output[cve["cve_number"]]["paths"].split(",")
                        self.total_files -= len(path_list)
                        path_list.extend(cve["paths"].split(","))
                        # remove duplicate paths(if any)
                        path_list = list(set(path_list))
                        self.total_files += len(path_list)
                        output[cve["cve_number"]]["path"] = path_list

        return list(output.values())

    @staticmethod
    def get_intermediate_cve_scanner(cve_data_list, score) -> list[CVEScanner]:
        """Returns a list of CVEScanner parsed objects when a list of cve_data json like list is passed"""
        cve_scanner_list = []
        for inter_data in cve_data_list:
            with CVEScanner(score=score) as cve_scanner:
                triage_data: TriageData
                parsed_data: dict[ProductInfo, TriageData] = {}

                parsed_data = parse_data_from_json(
                    inter_data["report"] if "report" in inter_data else inter_data
                )

                for product_info, triage_data in parsed_data.items():
                    LOGGER.debug(f"{product_info}, {triage_data}")
                    cve_scanner.get_cves(product_info, triage_data)

                cve_scanner_list.append(cve_scanner)

        return cve_scanner_list


def parse_data_from_json(
    json_data: list[dict[str, str]]
) -> dict[ProductInfo, TriageData]:
    """Parse CVE JSON dictionary to Dict[ProductInfo, TriageData]"""

    parsed_data: dict[ProductInfo, TriageData] = defaultdict(dict)

    for row in json_data:
        product_info = ProductInfo(
            row["vendor"].strip(),
            row["product"].strip(),
            row["version"].strip(),
            row.get("location", "location/to/product").strip(),
        )
        parsed_data[product_info][row.get("cve_number", "").strip() or "default"] = {
            "remarks": Remarks(str(row.get("remarks", "")).strip()),
            "comments": row.get("comments", "").strip(),
            "severity": row.get("severity", "").strip(),
        }

        parsed_data[product_info]["paths"] = set(
            map(lambda x: x.strip(), row.get("paths", "").split(","))
        )
    return parsed_data


def get_severity_count(reports: list[dict[str, str]] = []) -> dict[str, int]:
    """Returns a list of Severity counts for intermediate report"""
    severity_count = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}

    for cve in reports:
        if "severity" in cve and cve["severity"] in severity_count:
            severity_count[cve["severity"]] += 1
        else:
            severity_count["UNKNOWN"] += 1

    return severity_count
