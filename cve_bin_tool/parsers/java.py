# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import defusedxml.ElementTree as ET

from cve_bin_tool.parsers import Parser
from cve_bin_tool.util import ProductInfo, ScanInfo
from cve_bin_tool.validator import validate_pom


class JavaParser(Parser):
    def __init__(self, cve_db, logger, validate=True):
        super().__init__(cve_db, logger)
        self.validate = validate

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
            vendor = vendor_package_pair[0]["vendor"]
            file_path = self.filename
            self.logger.debug(f"{file_path} {product} {version} by {vendor}")
            return ScanInfo(ProductInfo(vendor, product, version), file_path)
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
                product_info = self.find_vendor(product, version)
                if product_info is not None:
                    yield product_info

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
                                product_info = self.find_vendor(product.text, version)
                                if product_info is not None:
                                    yield product_info
        self.logger.debug(f"Done scanning file: {filename}")
