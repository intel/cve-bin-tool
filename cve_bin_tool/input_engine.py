# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Module: input_engine.py

This module provides the InputEngine class for parsing different input file formats in the CVE Bin Tool.

"""

import csv
import json
import re
from collections import defaultdict
from logging import Logger
from pathlib import Path
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
    """
    Class: InputEngine

    This class is responsible for parsing various input file formats (CSV, VEX, JSON) in the CVE Bin Tool.

    Attributes:
    - parsed_data (DefaultDict[ProductInfo, TriageData]): Dictionary containing parsed input data.

    Methods:
    - __init__(self, filename: str, logger: Logger = None, error_mode=ErrorMode.TruncTrace, filetype="autodetect"):
        Initializes the InputEngine with the specified filename, logger, error mode, and filetype.

    - parse_input(self) -> DefaultDict[ProductInfo, TriageData]:
        Parses the input file based on its type (CSV, VEX, JSON) and returns the parsed data.

    - input_csv(self) -> None:
        Parses input data from a CSV file.

    - input_json(self) -> None:
        Parses input data from a JSON file.

    - input_vex(self) -> None:
        Parses input data from a CycloneDX VEX file.

    - validate_product(self, product: str) -> bool:
        Validates if a product name conforms to the CPE 2.3 standard.

    - input_vex(self) -> None:
        Parses input data from a CycloneDX VEX file.

    - parse_data(self, fields: Set[str], data: Iterable) -> None:
        Parses common data structure for CSV and JSON input formats.

    """

    # parsed_data is a dictionary of vendor, product, version mapped to TriageData
    parsed_data: DefaultDict[ProductInfo, TriageData]

    def __init__(
        self,
        filename: str,
        logger: Logger = None,
        error_mode=ErrorMode.TruncTrace,
        filetype="autodetect",
    ):
        """
        Initializes the InputEngine instance.

        Args:
        - filename (str): Path to the input file.
        - logger (Logger, optional): Logger instance for logging messages.
        - error_mode (ErrorMode, optional): Error handling mode.
        - filetype (str, optional): Type of the input file (default is "autodetect").

        """
        self.filename = str(Path(filename).resolve())
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.error_mode = error_mode
        self.filetype = filetype
        self.parsed_data = defaultdict(dict)
        # Connect to the database
        self.cvedb = CVEDB(version_check=False)

    def parse_input(self) -> DefaultDict[ProductInfo, TriageData]:
        """
        Parses the input file and returns the parsed data.

        Returns:
        - DefaultDict[ProductInfo, TriageData]: Parsed input data.

        """

        if not Path(self.filename).is_file():
            with ErrorHandler(mode=self.error_mode):
                raise FileNotFoundError(self.filename)
        if self.filename.endswith(".csv"):
            self.input_csv()
        elif self.filename.endswith(".vex") or self.filetype == "vex":
            self.input_vex()
        elif self.filename.endswith(".json"):
            self.input_json()
        return self.parsed_data

    def input_csv(self) -> None:
        """
        Parses input data from a CSV file.

        Raises:
        - InvalidCsvError: If the CSV file is invalid.

        """
        with open(self.filename) as csv_file:
            csvdata = csv.DictReader(csv_file)
            if csvdata is None or csvdata.fieldnames is None:
                with ErrorHandler(mode=self.error_mode):
                    raise InvalidCsvError(self.filename)

            self.parse_data(set(csvdata.fieldnames), csvdata)

    def input_json(self) -> None:
        """
        Parses input data from a JSON file.

        Raises:
        - InvalidJsonError: If the JSON file is invalid.

        """
        with open(self.filename) as json_file:
            json_data = json.load(json_file)
            if not json_data or not isinstance(json_data, list):
                with ErrorHandler(mode=self.error_mode):
                    raise InvalidJsonError(self.filename)

            self.parse_data(set(json_data[0].keys()), json_data)

    def validate_product(self, product: str) -> bool:
        """
        Validates if a product name conforms to the CPE 2.3 standard.

        Args:
        - product (str): Product name.

        Returns:
        - bool: True if the product name is valid, False otherwise.

        """
        """
        Ensure product name conforms to CPE 2.3 standard.
        See https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd for naming specification
        """
        cpe_regex = r"\A([A-Za-z0-9\._\-~ %])+\Z"
        return re.search(cpe_regex, product) is not None

    def input_vex(self) -> None:
        """
        Parses input data from a VEX file.
        """
        with open(self.filename) as json_file:
            json_data = json.load(json_file)

        # Only handle CycloneDX VEX file format
        if json_data["bomFormat"] == "CycloneDX":
            self.input_vex_cyclone_dx(json_data)

    def input_vex_cyclone_dx(self, json_data):
        """
        Parses input data from a CycloneDX VEX file.
        """

        def strip_remark(detail) -> str:
            detail = re.sub("^" + Remarks.NewFound.name + "(: )?", "", detail)
            detail = re.sub("^" + Remarks.Unexplored.name + "(: )?", "", detail)
            detail = re.sub("^" + Remarks.Confirmed.name + "(: )?", "", detail)
            detail = re.sub("^" + Remarks.Mitigated.name + "(: )?", "", detail)
            detail = re.sub("^" + Remarks.FalsePositive.name + "(: )?", "", detail)
            detail = re.sub("^" + Remarks.NotAffected.name + "(: )?", "", detail)
            return detail

        # Map CycloneDX v1.4 anaylsis state to the Remarks enumeration.
        remarks_lookup = {
            "resolved": Remarks.Mitigated,
            "resolved_with_pedigree": Remarks.Mitigated,
            "exploitable": Remarks.Confirmed,
            "in_triage": Remarks.Unexplored,
            "false_positive": Remarks.FalsePositive,
            "not_affected": Remarks.NotAffected,
        }

        # Not all data from the BOM needs to be read because it will be updated from the
        # CVE DB. The analysis fields may have been updated in the VEX and should be
        # read.
        for vulnerability in json_data["vulnerabilities"]:
            id = vulnerability["id"]
            analysis_state = vulnerability["analysis"]["state"].lower()
            remarks = Remarks.Unexplored
            if analysis_state in remarks_lookup:
                remarks = remarks_lookup[analysis_state]
            justification = vulnerability["analysis"].get("justification", None)
            response = vulnerability["analysis"].get("response", None)
            comments = strip_remark(vulnerability["analysis"]["detail"])
            severity = None
            if "ratings" in vulnerability:
                for rating in vulnerability["ratings"]:
                    severity = rating["severity"].upper()
            for affect in vulnerability["affects"]:
                product_info = self.decode_bom_ref(affect["ref"])

                if product_info is not None:
                    self.parsed_data[product_info][id.strip() or "default"] = {
                        "remarks": remarks,
                        "comments": comments.strip(),
                        "response": response,
                    }
                    if justification:
                        self.parsed_data[product_info][id.strip() or "default"][
                            "justification"
                        ] = justification.strip()
                    if severity:
                        self.parsed_data[product_info][id.strip() or "default"][
                            "severity"
                        ] = severity.strip()
                    self.parsed_data[product_info]["paths"] = {}

    def decode_bom_ref(self, ref) -> ProductInfo:
        """
        Decodes the BOM reference for each component.

        Args:
        - ref (str): BOM reference string

        Returns:
        - bool: ProductInfo object containing the vendor, product, and version.

        """
        # urn:cbt:{bom_version}/{vendor}#{product}-{version}
        urn_cbt_ref = re.compile(
            r"urn:cbt:(?P<bom_version>.*?)\/(?P<vendor>.*?)#(?P<product>.*?)-(?P<version>.*)"
        )

        # This URN was added to support CPE's that have dashes in their version field.
        # urn:cbt:{bom_version}/{vendor}#{product}:{version}
        urn_cbt_ext_ref = re.compile(
            r"urn:cbt:(?P<bom_version>.*?)\/(?P<vendor>.*?)#(?P<product>.*?):(?P<version>.*)"
        )

        # urn:cdx:serialNumber/version#bom-ref (https://cyclonedx.org/capabilities/bomlink/)
        urn_cdx = re.compile(
            r"urn:cdx:(?P<bomSerialNumber>.*?)\/(?P<bom_version>.*?)#(?P<bom_ref>.*)"
        )

        if urn_cbt_ext_ref.match(ref):
            urn_dict = urn_cbt_ext_ref.match(ref).groupdict()
            vendor = urn_dict["vendor"]
            product = urn_dict["product"]
            version = urn_dict["version"]
        elif urn_cbt_ref.match(ref):
            urn_dict = urn_cbt_ref.match(ref).groupdict()
            vendor = urn_dict["vendor"]
            product = urn_dict["product"]
            version = urn_dict["version"]
        elif urn_cdx.match(ref):
            urn_dict = urn_cdx.match(ref).groupdict()
            cdx_bom_ref = urn_dict["bom_ref"]
            # Try to decode the CDX BOM reference. This can be any unique identifier but may contain
            #   product:version
            #   or it could be a Package URL.
            try:
                product, version = cdx_bom_ref.rsplit("-", 1)
            except ValueError:
                product, version = None, None
            vendor = "UNKNOWN"
        else:
            product = None
            version = None
            vendor = None

        product_info = None
        if product is not None and self.validate_product(product):
            product_info = ProductInfo(vendor.strip(), product.strip(), version.strip())

        return product_info

    def parse_data(self, fields: Set[str], data: Iterable) -> None:
        """
        Parses common data structure for CSV and JSON input formats.

        Args:
        - fields (Set[str]): Set of fields present in the input data.
        - data (Iterable): Iterable containing the input data.

        Raises:
        - MissingFieldsError: If required fields are missing in the input data.

        """
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
