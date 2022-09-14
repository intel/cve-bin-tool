# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import csv
import json
import os
import re
from collections import defaultdict
from logging import Logger
from typing import Any, DefaultDict, Dict, Iterable, Set, Union

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.error_handler import (
    ErrorHandler,
    ErrorMode,
    InvalidCsvError,
    InvalidJsonError,
    MissingFieldsError,
)
from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import ProductInfo, Remarks

# TriageData is dictionary of cve_number mapped to dictionary of remarks, comments and custom severity
TriageData = Dict[str, Union[Dict[str, Any], Set[str]]]


class InputEngine:
    # parsed_data is a dictionary of vendor, product, version mapped to TriageData
    parsed_data: DefaultDict[ProductInfo, TriageData]

    def __init__(
        self, filename: str, logger: Logger = None, error_mode=ErrorMode.TruncTrace
    ):
        self.filename = os.path.abspath(filename)
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.error_mode = error_mode
        self.parsed_data = defaultdict(dict)
        # Connect to the database
        self.cvedb = CVEDB(version_check=False)

    def parse_input(self) -> DefaultDict[ProductInfo, TriageData]:
        if not os.path.isfile(self.filename):
            with ErrorHandler(mode=self.error_mode):
                raise FileNotFoundError(self.filename)
        if self.filename.endswith(".csv"):
            self.input_csv()
        elif self.filename.endswith(".json"):
            self.input_json()
        elif self.filename.endswith(".vex"):
            self.input_vex()
        return self.parsed_data

    def input_csv(self) -> None:
        with open(self.filename) as csv_file:
            csvdata = csv.DictReader(csv_file)
            if csvdata is None or csvdata.fieldnames is None:
                with ErrorHandler(mode=self.error_mode):
                    raise InvalidCsvError(self.filename)

            self.parse_data(set(csvdata.fieldnames), csvdata)

    def input_json(self) -> None:
        with open(self.filename) as json_file:
            json_data = json.load(json_file)
            if not json_data or not isinstance(json_data, list):
                with ErrorHandler(mode=self.error_mode):
                    raise InvalidJsonError(self.filename)

            self.parse_data(set(json_data[0].keys()), json_data)

    def validate_product(self, product: str) -> bool:
        """
        Ensure product name conforms to CPE 2.3 standard.
        See https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd for naming specification
        """
        cpe_regex = r"\A([A-Za-z0-9\._\-~ %])+\Z"
        return re.search(cpe_regex, product) is not None

    def input_vex(self) -> None:
        analysis_state = {
            "under_review": Remarks.Unexplored,
            "in_triage": Remarks.Unexplored,
            "exploitable": Remarks.Confirmed,
            "not_affected": Remarks.Mitigated,
        }
        with open(self.filename) as json_file:
            json_data = json.load(json_file)
            # Only handle CycloneDX VEX file format
            if json_data["bomFormat"] == "CycloneDX":
                for vulnerability in json_data["vulnerabilities"]:
                    id = vulnerability["id"]
                    analysis_status = vulnerability["analysis"]["state"].lower()
                    state = Remarks.Unexplored
                    if analysis_status in analysis_state:
                        state = analysis_state[analysis_status]
                    comments = vulnerability["analysis"]["detail"]
                    for rating in vulnerability["ratings"]:
                        severity = rating["severity"]
                    for affect in vulnerability["affects"]:
                        ref = affect["ref"]
                        version = None
                        vendor = None
                        if "#" in ref:
                            # Extract product information after # delimiter
                            p = ref.split("#")[1]
                            # Last element is version, rest is product which may include -
                            elements = p.rsplit("-", 1)
                            product = elements[0]
                            version = elements[1]
                            # Now find vendor
                            vendor_package_pair = self.cvedb.get_vendor_product_pairs(
                                product
                            )
                            if vendor_package_pair != []:
                                vendor = vendor_package_pair[0]["vendor"]
                        if version is not None and self.validate_product(product):
                            product_info = ProductInfo(
                                vendor.strip(), product.strip(), version.strip()
                            )
                            self.parsed_data[product_info][id.strip() or "default"] = {
                                "remarks": state,
                                "comments": comments.strip(),
                                "severity": severity.strip(),
                            }
                            self.parsed_data[product_info]["paths"] = {""}

    def parse_data(self, fields: Set[str], data: Iterable) -> None:
        required_fields = {"vendor", "product", "version"}
        missing_fields = required_fields - fields
        if missing_fields != set():
            with ErrorHandler(mode=self.error_mode):
                raise MissingFieldsError(f"{missing_fields} are required fields")

        for row in data:
            product_info = ProductInfo(
                row["vendor"].strip(), row["product"].strip(), row["version"].strip()
            )
            self.parsed_data[product_info][
                row.get("cve_number", "").strip() or "default"
            ] = {
                "remarks": Remarks(str(row.get("remarks", "")).strip()),
                "comments": row.get("comments", "").strip(),
                "severity": row.get("severity", "").strip(),
            }
            self.parsed_data[product_info]["paths"] = set(
                map(lambda x: x.strip(), row.get("paths", "").split(","))
            )
