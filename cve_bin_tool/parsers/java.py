# NOTE: DONE
# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
"""Script containing all functionalities relating to parsing of Java-based files."""
import re

import defusedxml.ElementTree as ET

from cve_bin_tool.parsers import Parser
from cve_bin_tool.util import ProductInfo, ScanInfo
from cve_bin_tool.validator import validate_pom


class JavaParser(Parser):
    """Class to handle parsing Java-based Packages."""

    PARSER_MATCH_FILENAMES = [
        "pom.xml",
    ]

    def __init__(self, cve_db, logger, validate=True):
        super().__init__(cve_db, logger)
        self.validate = validate
        self.purl_pkg_type = "maven"

    def generate_purl(self, product, vendor="", qualifier={}, subpath=None):
        """Generates PURL after normalizing all components of a Maven package."""
        # Normalize product
        product = re.sub(r"[^a-zA-Z0-9._-]", "", product).lower()

        if not product:
            return None

        purl = super().generate_purl(
            product,
            vendor,
            qualifier,
            subpath,
        )

        return purl

    def find_vendor(self, product, version):
        """Find vendor for Java product"""
        vendor_package_pair = self.cve_db.get_vendor_product_pairs(product)
        # If no match, try alternative product name.
        # Apache product names are stored as A_B in NVD database but often called A-B
        # Some packages have -parent appended to product which is not in NVD database
        if vendor_package_pair == [] and "-" in product:
            self.logger.debug(f"Try alternative product {product}")
            # Remove parent appendage
            if "-parent" in product:
                product = product.replace("-parent", "")
            product = product.replace("-", "_")
            vendor_package_pair = self.cve_db.get_vendor_product_pairs(product)
        if vendor_package_pair != []:
            info = []
            for pair in vendor_package_pair:
                vendor = pair["vendor"]
                file_path = self.filename
                location = pair.get("location", self.filename)
                self.logger.debug(f"{file_path} {product} {version} by {vendor}")
                info.append(
                    ScanInfo(ProductInfo(vendor, product, version, location), file_path)
                )
            return info
        return None

    def run_checker(self, filename):
        """Process maven pom.xml file and extract product and dependency details"""
        self.filename = filename
        continue_processing = True
        if self.validate:
            continue_processing = validate_pom(filename)
            self.logger.debug(f"Validation of {filename} - {continue_processing}")
        if continue_processing:
            tree = ET.parse(filename)
            # Find root element
            root = tree.getroot()
            # Extract schema
            schema = root.tag[: root.tag.find("}") + 1]
            parent = root.find(schema + "parent")
            version = None
            product = None
            file_path = self.filename
            # Parent tag is optional.
            if parent is None:
                product = root.find(schema + "artifactId").text
                version = root.find(schema + "version").text
            if version is None and parent is not None:
                version = parent.find(schema + "version").text

            # If no version has been found, set version to UNKNOWN
            if version is None:
                version = "UNKNOWN"

            # Check valid version identifier (i.e. starts with a digit)
            if not version[0].isdigit():
                self.logger.debug(f"Invalid {version} detected in {filename}")
                version = None
            if product is None and parent is not None:
                product = parent.find(schema + "artifactId").text
            if product is not None and version is not None:
                purl = self.generate_purl(product)
                product_info, result = self.find_vendor_from_purl(purl, version)
                if not result:
                    product_info = self.find_vendor(product, version)
                product_info = self.mismatch(purl, product_info)
                if product_info is not None:
                    yield from product_info

            # Some version strings are defined as properties.
            # Build up dictionary of values in same format ${name} : {value}
            properties = root.find(schema + "properties")
            java_props = {}
            if properties is not None:
                for prop in properties:
                    # Remove the schema from tag
                    tag = prop.tag[prop.tag.find("}") + 1 :]
                    java_props["${" + tag + "}"] = prop.text

            # Scan for any dependencies referenced in file
            dependencies = root.find(schema + "dependencies")
            if dependencies is not None:
                for dependency in dependencies.findall(schema + "dependency"):
                    product = dependency.find(schema + "artifactId")
                    if product is not None:
                        version = dependency.find(schema + "version")
                        if version is not None:
                            version = version.text
                            if version[0] == "$":
                                # Check if version specified in properties
                                if version in java_props:
                                    self.logger.debug(
                                        f"Translate {version} to {java_props[version]}"
                                    )
                                    version = java_props[version]
                            self.logger.debug(f"{file_path} {product.text} {version}")
                            if version[0].isdigit():
                                # Valid version identifier
                                purl = self.generate_purl(product.text)
                                product_info, result = self.find_vendor_from_purl(
                                    purl, version
                                )
                                if not result:
                                    product_info = self.find_vendor(
                                        product.text, version
                                    )
                                product_info = self.mismatch(purl, product_info)
                                if product_info is not None:
                                    yield from product_info
        self.logger.debug(f"Done scanning file: {filename}")
