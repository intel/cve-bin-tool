# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path
from typing import Dict, List

from lib4sbom.cyclonedx.cyclonedx_parser import CycloneDXParser
from lib4sbom.sbom import SBOM, SBOMData
from lib4sbom.spdx.spdx_parser import SPDXParser


class SBOMParser:
    """
    Simple SBOM Parser.

    Parameters
    ----------
    sbom_type : string
        The type of SBOM (either spdx, cyclonedx or auto)

        auto is used to automatically work out the SBOM type

        Default is auto
    """

    def __init__(self, sbom_type: str = "auto"):
        self.debug = os.getenv("LIB4SBOM_DEBUG") is not None
        self.sbom_type = sbom_type
        self.document = None
        self.files = None
        self.packages = None
        self.relationships = None
        self.vulnerabilities = None
        self.services = None
        self.licenses = None
        self.sbom = SBOM(self.sbom_type)

    def parse_file(self, filename: str) -> None:
        """Parses a SBOM file

        Parameters
        ----------
        filename : string
            The filename of the SBOM
        """
        # Check file exists
        invalid_file = True
        if len(filename) > 0:
            # Check path
            filePath = Path(filename)
            # Check path exists and valid file
            if filePath.exists() and filePath.is_file():
                # Assume that processing can proceed
                invalid_file = False

        if invalid_file:
            raise FileNotFoundError

        # Set up parser
        if self.sbom_type == "cyclonedx":
            self.parser = CycloneDXParser()
        else:
            # Default parser is SPDX
            self.parser = SPDXParser()

        try:
            if self.sbom_type == "auto":
                # Work out the SBOM type for file
                # Assume SPDX...
                self.sbom_type = "spdx"
                (
                    self.document,
                    self.files,
                    self.packages,
                    self.relationships,
                    self.vulnerabilities,
                    self.services,
                    self.licenses,
                ) = self.parser.parse(filename)
                # but if no packages or files found, assume it must be CycloneDX
                if (
                    len(self.packages) == 0
                    and len(self.files) == 0
                    and len(self.vulnerabilities) == 0
                ):
                    self.sbom_type = "cyclonedx"
                    self.parser = CycloneDXParser()
                    (
                        self.document,
                        self.files,
                        self.packages,
                        self.relationships,
                        self.vulnerabilities,
                        self.services,
                        self.licenses,
                    ) = self.parser.parse(filename)
            else:
                (
                    self.document,
                    self.files,
                    self.packages,
                    self.relationships,
                    self.vulnerabilities,
                    self.services,
                    self.licenses,
                ) = self.parser.parse(filename)
            self.sbom.add_files(self.files)
            self.sbom.add_packages(self.packages)
            self.sbom.add_relationships(self.relationships)
            if len(self.document) > 0:
                self.sbom.add_document(self.document.get_document())
            if len(self.vulnerabilities) > 0:
                self.sbom.add_vulnerabilities(self.vulnerabilities)
            if len(self.services) > 0:
                self.sbom.add_services(self.services)
            if len(self.licenses) > 0:
                self.sbom.add_licenses(self.licenses)
            self.sbom.set_type(self.sbom_type)
        except KeyError:
            if self.debug:
                print("Key Error")
        except TypeError:
            if self.debug:
                print("Type Error")

    def set_type(self, sbom_type: str = "auto") -> None:
        self.sbom_type = sbom_type

    def get_sbom(self) -> SBOMData:
        """Return the constituent components of SBOM
        Returns
        -------
        SBOM : SBOMData object
        """
        return self.sbom.get_sbom()

    def get_type(self) -> str:
        """Return the type of SBOM
        Returns
        -------
        SBOMtype : string
        """
        return self.sbom.get_type()

    def get_files(self) -> List[Dict]:
        """Returns the file elements from within a parsed SBOM
        Returns
        -------
        files : list of SBOMfile objects

        """
        return self.sbom.get_files()

    def get_packages(self) -> List[Dict]:
        """Returns the package elements from within a parsed SBOM
        Returns
        -------
        packages : list of SBOMPackage objects

        """
        return self.sbom.get_packages()

    def get_relationships(self) -> List[List[str]]:
        """Returns the relationship elements from within a parsed SBOM
        Returns
        -------
        relationships : list of SBOMRelationship objects

        """
        return self.sbom.get_relationships()

    def get_document(self) -> Dict:
        """Returns the relationship elements from within a parsed SBOM
        Returns
        -------
        relationships : list of SBOMDocument objects

        """
        return self.sbom.get_document()

    def get_vulnerabilities(self) -> List[Dict]:
        """Returns the vulnerability elements from within a parsed SBOM
        Returns
        -------
        relationships : list of SBOMVulnerability objects

        """
        return self.sbom.get_vulnerabilities()

    def get_services(self) -> List[Dict]:
        """Returns the service elements from within a parsed SBOM
        Returns
        -------
        services : list of SBOMService objects

        """
        return self.sbom.get_services()

    def get_licenses(self) -> List[Dict]:
        """Returns the license elements from within a parsed SBOM
        Returns
        -------
        licenses : list of SBOMLicense objects

        """
        return self.sbom.get_licenses()
