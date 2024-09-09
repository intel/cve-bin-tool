# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import re
import sys
from collections import defaultdict
from logging import Logger
from pathlib import Path

import defusedxml.ElementTree as ET
from lib4sbom.parser import SBOMParser
from packageurl import PackageURL

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.input_engine import TriageData
from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import (
    ProductInfo,
    Remarks,
    decode_cpe22,
    decode_cpe23,
    find_product_location,
    validate_location,
    validate_serialNumber,
)
from cve_bin_tool.validator import validate_cyclonedx, validate_spdx, validate_swid


class SBOMParse:
    """
    Class: SBOMParse

    This class is responsible for parsing various SBOM file formats (SPDX, CycloneDX, SWID) in the CVE Bin Tool.

    It provides methods for scanning SBOM files, parsing them, and retrieving vendor information.

    Attributes:
    - sbom_data (DefaultDict[ProductInfo, TriageData]): Dictionary containing parsed SBOM data.

    """

    SBOMtype = ["spdx", "cyclonedx", "swid"]

    sbom_data: defaultdict[ProductInfo, TriageData]

    def __init__(
        self,
        filename: str,
        sbom_type: str = "spdx",
        logger: Logger | None = None,
        validate: bool = True,
    ):
        self.filename = filename
        self.sbom_data = defaultdict(dict)
        self.type = "unknown"
        if sbom_type in self.SBOMtype:
            self.type = sbom_type
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.validate = validate
        self.serialNumber = ""

        # Connect to the database
        self.cvedb = CVEDB(version_check=False)

    def parse_sbom(self) -> dict[ProductInfo, TriageData]:
        """
        Parses the SBOM input file and returns the product information and
        corresponding triage data.

        Returns:
        - dict[ProductInfo, TriageData]: Parsed SBOM data.

        """
        self.logger.debug(
            f"Processing SBOM {self.filename} of type {self.type.upper()}"
        )
        modules = []
        try:
            if Path(self.filename).exists():
                if self.type == "swid":
                    modules = self.parse_swid(self.filename)
                else:
                    modules = self.parse_cyclonedx_spdx()
        except (KeyError, FileNotFoundError, ET.ParseError) as e:
            LOGGER.debug(e, exc_info=True)

        LOGGER.debug(
            f"The number of modules identified in SBOM - {len(modules)}\n{modules}"
        )

        # Now process list of modules to create [vendor, product, version] tuples
        parsed_data: list[ProductInfo] = []
        for module_vendor, product, version in modules:
            # Using lower to normalize product names across databases
            product = product.lower()

            if module_vendor is None:
                # Now add vendor to create product record....
                vendor_set = self.get_vendor(product)
                for vendor in vendor_set:
                    # if vendor is not None:
                    location = find_product_location(product)
                    if location is None:
                        location = "NotFound"
                    if validate_location(location) is False:
                        raise ValueError(f"Invalid location {location} for {product}")
                    parsed_data.append(ProductInfo(vendor, product, version, location))
            else:
                location = find_product_location(product)
                if location is None:
                    location = "NotFound"
                if validate_location(location) is False:
                    raise ValueError(f"Invalid location {location} for {product}")
                parsed_data.append(
                    ProductInfo(module_vendor, product, version, location)
                )

        for row in parsed_data:
            self.sbom_data[row]["default"] = {
                "remarks": Remarks.NewFound,
                "comments": "",
                "severity": "",
            }
            self.sbom_data[row]["paths"] = set(map(lambda x: x.strip(), "".split(",")))

        LOGGER.debug(f"SBOM Data {self.sbom_data}")
        return self.sbom_data

    def common_prefix_split(self, product, version) -> list[ProductInfo]:
        """If the product have '-' in name try splitting it and try common prefixes.
        currently not being used, proposed to be used in future"""
        parsed_data: list[ProductInfo] = []
        found_common_prefix = False
        common_prefix = (
            "perl-",
            "golang-",
            "rubygem-",
            "python-",
            "py3-",
            "python3-",
            "python2-",
            "rust-",
            "nodejs-",
        )
        for prefix in common_prefix:
            if product.startswith(prefix):
                common_prefix_product = product[len(prefix) :]
                common_prefix_vendor = self.get_vendor(common_prefix_product)
                if len(common_prefix_vendor) > 1 or (
                    len(common_prefix_vendor) == 1
                    and common_prefix_vendor[0] != "UNKNOWN"
                ):
                    location = find_product_location(common_prefix_product)
                    if location is None:
                        location = "NotFound"
                    if validate_location(location) is False:
                        raise ValueError(f"Invalid location {location} for {product}")
                    found_common_prefix = True
                    for vendor in common_prefix_vendor:
                        parsed_data.append(
                            ProductInfo(
                                vendor, common_prefix_product, version, location
                            )
                        )
                break
        if not found_common_prefix:
            # if vendor not found after removing common prefix try splitting it
            LOGGER.debug(
                f"No Vendor found for {product}, trying splitted product. "
                "Some results may be inaccurate due to vendor identification limitations."
            )
            splitted_product = product.split("-")
            for sp in splitted_product:
                temp = self.get_vendor(sp)
                if len(temp) > 1 or (len(temp) == 1 and temp[0] != "UNKNOWN"):
                    for vendor in temp:
                        location = find_product_location(sp)
                        if location is None:
                            location = "NotFound"
                        if validate_location(location) is False:
                            raise ValueError(
                                f"Invalid location {location} for {product}"
                            )
                        # if vendor is not None:
                        parsed_data.append(ProductInfo(vendor, sp, version, location))
        return parsed_data

    def get_vendor(self, product: str) -> list:
        """
        Get the list of vendors for the product name.

        There may be more than one vendor for a given product name and all
        matches are returned.

        Args:
        - product (str): Product name.

        Returns:
        - list: The list of vendors for the product

        """
        vendorlist: list[str] = []
        vendor_package_pair = self.cvedb.get_vendor_product_pairs(product)
        if vendor_package_pair:
            # To handle multiple vendors, return all combinations of product/vendor mappings
            for v in vendor_package_pair:
                vendor = v["vendor"]
                vendorlist.append(vendor)
        else:
            vendorlist.append("UNKNOWN")
        return vendorlist

    def is_valid_string(self, string_type: str, ref_string: str) -> bool:
        """
        Validate the CPE string is the correct form.

        Args:
        - ref_string (str): CPE strings
        - string_type (str): ref_string type. (cpe22 or cpe23)

        Returns:
        - bool: True if the ref_string parameter is a valid purl or cpe string, False otherwise.

        """
        string_pattern: str
        if string_type == "cpe23":
            string_pattern = r"^cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?\!\"#\$%&'\(\)\+,\-\.\/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?\!\"#\$%&'\(\)\+,\-\.\/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){4}"

        elif string_type == "cpe22":
            string_pattern = r"^[c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9\._\-~%]*){0,6}"

        return re.match(string_pattern, ref_string) is not None

    def parse_cyclonedx_spdx(self) -> [(str, str, str)]:
        """
        Parse the cyclonedx/spdx to extract a list of modules, including vendor, product, and version information.

        The parsed product information can be retrieved from different components of the SBOM, with the following order of preference:
        1. CPE 2.3 Identifiers
        2. CPE 2.2 Identifiers
        3. Package URLs (purl)
        4. Name and Version from the SBOM (Vendor will be unspecified)

        Returns:
        - List[(str, str, str)]: A list of tuples, each containing vendor, product, and version information for a module.

        """

        # Set up SBOM parser
        sbom_parser = SBOMParser(sbom_type=self.type)
        # Load SBOM
        sbom_parser.parse_file(self.filename)
        doc = sbom_parser.get_document()
        uuid = doc.get("uuid", "")
        if self.type == "cyclonedx":
            parts = uuid.split(":")
            if len(parts) == 3 and parts[0] == "urn" and parts[1] == "uuid":
                serialNumber = parts[2]
                if validate_serialNumber(serialNumber):
                    self.serialNumber = serialNumber
                else:
                    LOGGER.error(
                        f"The SBOM file '{self.filename}' has an invalid serial number."
                    )
                    return []
            else:
                LOGGER.error(
                    f"The SBOM file '{self.filename}' has an invalid serial number."
                )
                return []

        modules = []
        if self.validate and self.filename.endswith(".xml"):
            # Only for XML files
            if sbom_parser.get_type() == "spdx":
                valid_xml = validate_spdx(self.filename)
            else:
                valid_xml = validate_cyclonedx(self.filename)
            if not valid_xml:
                return modules
        packages = [x for x in sbom_parser.get_sbom()["packages"].values()]
        LOGGER.debug(f"Parsed SBOM {self.filename} {packages}")
        for package in packages:
            vendor = None
            package_name = None
            version = None

            # If Package URL or CPE record found, use this data in preference to package data
            ext_ref = package.get("externalreference")
            if ext_ref is not None:
                vendor, package_name, version = self.parse_ext_ref(ext_ref=ext_ref)

            # For any data not found in CPE or the Package URL get from package data
            if not vendor:
                pass  # Because no vendor was detected then all vendors with this named package
                # will be included in the output.

            if not package_name:
                package_name = package["name"]

            if (not version) and (package.get("version") is not None):
                version = package["version"]
            else:
                LOGGER.debug(f"No version found in {package}")

            if version:
                # Found at least package and version, save the results
                modules.append([vendor, package_name, version])

        LOGGER.debug(f"Parsed SBOM {self.filename} {modules}")
        return modules

    def parse_swid(self, sbom_file: str) -> list[list[str]]:
        """Parse SWID XML BOM file extracting package name and version"""
        modules: list[list[str]] = []
        if self.validate and not validate_swid(sbom_file):
            return modules
        tree = ET.parse(sbom_file)
        # Find root element
        root = tree.getroot()
        # Extract schema
        schema = root.tag[: root.tag.find("}") + 1]
        # schema = '{http://standards.iso.org/iso/19770/-2/2015/schema.xsd}'
        for component in root.findall(schema + "Link"):
            # Only if a component ....
            if component.get("rel") == "component":
                swid = component.get("href")
                if not swid:
                    raise KeyError(f"Could not find href in {component}")
                swid = swid.replace("%20", " ")
                modules.append(self.extract(swid))

        return modules

    def extract(self, swid: str) -> list[str]:
        """
        Extracts the product name and version from a SWID entry.
        args:
            swid: SWID entry
        returns:
            list containing product name and version
        """
        # Return parsed swid entry as [product, version] list item
        # Format of swid is "URI: <vendor>-<product>-<version>"
        item = swid[swid.find(":") + 1 :].split("-")
        # As some version numbers have leading 'v', it is removed
        return [item[0].strip(" "), item[1], item[2].upper().replace("V", "")]

    def parse_ext_ref(self, ext_ref) -> (str | None, str | None, str | None):
        """
        Parse external references in an SBOM to extract module information.

        Two passes are made through the external references, giving priority to CPE types,
        which will always match the CVE database.

        Args:
        - ext_ref (List[List[str]]): List of lists representing external references.
          Each inner list contains [category, type, locator].

        Returns:
        - Optional[Tuple[str | None, str | None, str | None]]: A tuple containing the vendor, product, and version
          information extracted from the external references, or None if not found.

        """
        decoded = {}
        for ref in ext_ref:
            ref_type = ref[1]
            ref_string = ref[2]
            if ref_type == "cpe23Type" and self.is_valid_string("cpe23", ref_string):
                decoded["cpe23Type"] = decode_cpe23(ref_string)

            elif ref_type == "cpe22Type" and self.is_valid_string("cpe22", ref_string):
                decoded["cpe22Type"] = decode_cpe22(ref_string)

            elif ref_type == "purl":
                # Validation of purl is performed implicitly within the decode_purl function
                decoded["purl"] = self.decode_purl(ref_string)

        # No ext-ref matches, return none
        if decoded.get("purl") is not None:
            LOGGER.debug("Found PURL")
            return decoded.get("purl")
        elif decoded.get("cpe23Type") is not None:
            LOGGER.debug("Found CPE23")
            return decoded.get("cpe23Type")
        elif decoded.get("cpe22Type") is not None:
            LOGGER.debug("Found CPE22")
            return decoded.get("cpe22Type")
        else:
            LOGGER.debug("Nothing found")
            return [None, None, None]

    def decode_purl(self, purl) -> (str | None, str | None, str | None):
        """
        Decode a Package URL (purl) to extract version information.

        Args:
        - purl (str): Package URL (purl) string.

        Returns:
        - Tuple[str | None, str | None, str | None]: A tuple containing the vendor (which is always None for purl),
          product, and version information extracted from the purl string, or None if the purl is invalid or incomplete.

        """
        vendor = None  # Because the vendor and product identifiers in the purl don't always align
        product = None  # with the CVE DB, only the version is parsed.
        version = None
        # Process purl identifier
        purl_info = PackageURL.from_string(purl).to_dict()
        version = purl_info.get("version")

        return [vendor or None, product or None, version or None]


if __name__ == "__main__":

    file = sys.argv[1]
    sbom = SBOMParse(file)
    sbom.scan_file()
