# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any, DefaultDict, Dict, Set, Union

from lib4vex.parser import VEXParser

from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import ProductInfo, Remarks, decode_bom_ref, decode_purl

TriageData = Dict[str, Union[Dict[str, Any], Set[str]]]


class VEXParse:
    """
    A class for parsing VEX files and extracting necessary fields from the vulnerabilities.

    Attributes:
    - filename (str): The path to the VEX file.
    - vextype (str): The type of VEX file.
    - logger: The logger object for logging messages.
    - parsed_data: A dictionary to store the parsed data.
    - serialNumbers: serialNumbers from the bom_link used to check linkage with sbom.

    Methods:
    - __init__(self, filename: str, vextype: str, logger=None): Initializes the VEXParse object.
    - parse_vex(self) -> DefaultDict[ProductInfo, TriageData]: Parses the VEX file and extracts the necessary fields from the vulnerabilities.
    - process_metadata(self) -> None: Processes the metadata.
    - process_product(self) -> None: Processes the product information.
    - process_vulnerabilities(self, vulnerabilities) -> None: Processes the vulnerabilities and extracts the necessary fields.
    """

    analysis_state = {
        "cyclonedx": {
            "in_triage": Remarks.NewFound,
            "exploitable": Remarks.Confirmed,
            "resolved": Remarks.Mitigated,
            "false_positive": Remarks.FalsePositive,
            "not_affected": Remarks.NotAffected,
        },
        "csaf": {
            "first_affected": Remarks.NewFound,
            "first_fixed": Remarks.Mitigated,
            "fixed": Remarks.Mitigated,
            "known_affected": Remarks.Confirmed,
            "known_not_affected": Remarks.NotAffected,
            "last_affected": Remarks.Confirmed,
            "recommended": Remarks.Mitigated,
            "under_investigation": Remarks.NewFound,
        },
        "openvex": {
            "not_affected": Remarks.NotAffected,
            "affected": Remarks.Confirmed,
            "fixed": Remarks.Mitigated,
            "under_investigation": Remarks.NewFound,
        },
    }

    def __init__(self, filename: str, vextype: str, logger=None):
        self.filename = filename
        self.vextype = vextype
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.parsed_data = {}
        self.serialNumbers = set()

    def parse_vex(self) -> DefaultDict[ProductInfo, TriageData]:
        """Parses the VEX file and extracts the necessary fields from the vulnerabilities."""
        vexparse = VEXParser(vex_type=self.vextype)
        vexparse.parse(self.filename)
        if self.vextype == "auto":
            self.vextype = vexparse.get_type()

        self.logger.info(f"Parsed Vex File: {self.filename} of type: {self.vextype}")
        self.logger.debug(f"VEX Vulnerabilities: {vexparse.get_vulnerabilities()}")
        self.__process_vulnerabilities(vexparse.get_vulnerabilities())
        self.__process_metadata(vexparse.get_metadata())
        self.__process_product(vexparse.get_product())
        self.__extract_product_info()
        return self.parsed_data

    def __extract_product_info(self):
        """Extracts the product information from the parsed vex file"""
        product_info = {}
        if self.vextype == "cyclonedx":
            # release and vendor is not available in cyclonedx
            product_info["product"] = self.parsed_metadata.get("name")
            product_info["release"] = ""
            product_info["vendor"] = ""
        elif self.vextype == "csaf":
            csaf_product = self.parsed_product.get("CSAFPID_0001", {})
            if csaf_product:
                product_info["product"] = csaf_product.get("product")
                product_info["release"] = csaf_product.get("version")
                product_info["vendor"] = csaf_product.get("vendor")
        elif self.vextype == "openvex":
            # product and release is not available in openvex
            product_info["product"] = ""
            product_info["release"] = ""
            product_info["vendor"] = self.parsed_metadata.get("author")
        self.vex_product_info = product_info

    def __process_metadata(self, metadata) -> None:
        self.parsed_metadata = metadata

    def __process_product(self, product) -> None:
        self.parsed_product = product

    def __process_vulnerabilities(self, vulnerabilities) -> None:
        """ "processes the vulnerabilities and extracts the necessary fields from the vulnerability."""
        for vuln in vulnerabilities:
            # Extract necessary fields from the vulnerability
            cve_id = vuln.get("id")
            remarks = self.analysis_state[self.vextype][vuln.get("status")]
            justification = vuln.get("justification")
            response = vuln.get("remediation")
            comments = vuln.get("comment")

            # If the comment doesn't already have the justification prepended, add it
            if comments and justification and not comments.startswith(justification):
                comments = f"{justification}: {comments}"

            severity = vuln.get("severity")  # Severity is not available in Lib4VEX
            # Decode the bom reference for cyclonedx and purl for csaf and openvex
            product_info = None
            serialNumber = ""
            if self.vextype == "cyclonedx":
                decoded_ref = decode_bom_ref(vuln.get("bom_link"))
                if isinstance(decoded_ref, tuple) and not isinstance(
                    decoded_ref, ProductInfo
                ):
                    product_info, serialNumber = decoded_ref
                    self.serialNumbers.add(serialNumber)
                else:
                    product_info = decoded_ref
            elif self.vextype in ["openvex", "csaf"]:
                product_info = decode_purl(vuln.get("purl"))
            if product_info:
                cve_data = {
                    "remarks": remarks,
                    "comments": comments if comments else "",
                    "response": response if response else [],
                }
                if justification:
                    cve_data["justification"] = justification.strip()

                if severity:
                    cve_data["severity"] = severity.strip()

                if product_info not in self.parsed_data:
                    self.parsed_data[product_info] = {}
                self.parsed_data[product_info][cve_id.strip()] = cve_data

                if "paths" not in self.parsed_data[product_info]:
                    self.parsed_data[product_info]["paths"] = {}
        self.logger.debug(f"Parsed Vex Data: {self.parsed_data}")
