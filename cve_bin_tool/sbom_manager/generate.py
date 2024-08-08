# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from logging import Logger
from pathlib import Path
from typing import Optional

from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.generator import SBOMGenerator
from lib4sbom.sbom import SBOM

from cve_bin_tool.log import LOGGER
from cve_bin_tool.version import VERSION


class SBOMGenerate:
    """
    Class for generating SBOM (Software Bill of Materials)

    Methods:
        generate_sbom: Create SBOM package and generate SBOM file.
    """

    def __init__(
        self,
        all_product_data,
        filename="",
        sbom_type="spdx",
        sbom_format="tag",
        sbom_root="CVE-SCAN",
        logger: Optional[Logger] = None,
    ):
        self.all_product_data = all_product_data
        self.filename = filename
        self.sbom_type = sbom_type
        self.sbom_format = sbom_format
        self.sbom_root = sbom_root
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.sbom_packages = {}

    def generate_sbom(self) -> None:
        """Create SBOM package and generate SBOM file."""
        # Create SBOM
        sbom_relationships = []
        my_package = SBOMPackage()
        sbom_relationship = SBOMRelationship()

        # Create root package
        my_package.initialise()
        root_package = f'CVEBINTOOL-{Path(self.sbom_root).name.replace(".", "-")}'
        parent = f"SBOM_{root_package}"
        my_package.set_name(root_package)
        my_package.set_type("application")
        my_package.set_filesanalysis(False)
        my_package.set_downloadlocation(self.sbom_root)
        license = "NOASSERTION"
        my_package.set_licensedeclared(license)
        my_package.set_licenseconcluded(license)
        my_package.set_supplier("UNKNOWN", "NOASSERTION")

        # Store package data
        self.sbom_packages[(my_package.get_name(), my_package.get_value("version"))] = (
            my_package.get_package()
        )
        sbom_relationship.initialise()
        sbom_relationship.set_relationship(parent, "DESCRIBES", root_package)
        sbom_relationships.append(sbom_relationship.get_relationship())

        # Add dependent products
        for product_data in self.all_product_data:
            my_package.initialise()
            my_package.set_name(product_data.product)
            my_package.set_version(product_data.version)
            if product_data.vendor.casefold() != "UNKNOWN".casefold():
                my_package.set_supplier("Organization", product_data.vendor)
            my_package.set_licensedeclared(license)
            my_package.set_licenseconcluded(license)
            if not (
                (my_package.get_name(), my_package.get_value("version"))
                in self.sbom_packages
                and product_data.vendor == "unknown"
            ):
                location = product_data.location
                my_package.set_evidence(location)  # Set location directly
                self.sbom_packages[
                    (my_package.get_name(), my_package.get_value("version"))
                ] = my_package.get_package()
            sbom_relationship.initialise()
            sbom_relationship.set_relationship(
                root_package, "DEPENDS_ON", product_data.product
            )
            sbom_relationships.append(sbom_relationship.get_relationship())

        # Generate SBOM
        my_sbom = SBOM()
        my_sbom.add_packages(self.sbom_packages)
        my_sbom.add_relationships(sbom_relationships)
        my_generator = SBOMGenerator(
            sbom_type=self.sbom_type,
            format=self.sbom_format,
            application="cve-bin-tool",
            version=VERSION,
        )
        my_generator.generate(parent, my_sbom.get_sbom(), filename=self.filename)
