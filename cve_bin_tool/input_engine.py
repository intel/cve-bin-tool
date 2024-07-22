# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Module: input_engine.py

This module provides the InputEngine class for parsing different input file formats in the CVE Bin Tool.

"""

import csv
import json
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

    This class is responsible for parsing various input file formats (CSV, JSON) in the CVE Bin Tool.

    Attributes:
    - parsed_data (DefaultDict[ProductInfo, TriageData]): Dictionary containing parsed input data.

    Methods:
    - __init__(self, filename: str, logger: Logger = None, error_mode=ErrorMode.TruncTrace, filetype="autodetect"):
        Initializes the InputEngine with the specified filename, logger, error mode, and filetype.

    - parse_input(self) -> DefaultDict[ProductInfo, TriageData]:
        Parses the input file based on its type (CSV, JSON) and returns the parsed data.

    - input_csv(self) -> None:
        Parses input data from a CSV file.

    - input_json(self) -> None:
        Parses input data from a JSON file.

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
                row["vendor"].strip(),
                row["product"].strip(),
                row["version"].strip(),
                row.get("location", "location/to/product").strip(),
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
