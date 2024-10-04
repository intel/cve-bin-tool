# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from typing import Dict, List, NamedTuple


class SBOMData(NamedTuple):
    document: List
    files: Dict
    packages: Dict
    relationships: List
    vulnerabilities: Dict
    services: Dict
    licenses: List
    type: str
    version: str


class SBOM:
    """
    Simple SBOM Object.
    """

    def __init__(self, sbom_type: str = "auto"):
        self.sbom = {}
        self.set_type(sbom_type)

    def add_document(self, document: Dict):
        self.sbom["document"] = document

    def add_files(self, files: Dict):
        if len(files) > 0:
            self.sbom["files"] = files

    def add_packages(self, packages: Dict):
        if len(packages) > 0:
            self.sbom["packages"] = packages

    def add_relationships(self, relationships: List):
        self.sbom["relationships"] = relationships

    def add_vulnerabilities(self, vulnerabilities: Dict):
        self.sbom["vulnerabilities"] = vulnerabilities

    def add_services(self, services: Dict):
        self.sbom["services"] = services

    def add_licenses(self, licenses: List):
        self.sbom["licenses"] = licenses

    def add_data(self, sbom_data: SBOMData) -> None:
        for key, value in sbom_data.items():
            self.sbom[key] = value

    def set_type(self, sbom_type):
        self.sbom["type"] = sbom_type

    def set_version(self, version):
        self.sbom["version"] = version

    def set_uuid(self, uuid):
        if uuid.startswith("urn:uuid"):
            self.sbom["uuid"] = uuid

    def set_bom_version(self, version):
        self.sbom["bom_version"] = version

    def set_property(self, name, value):
        # Allow multiple entries
        property_entry = [name.strip(), value]
        if "property" in self.sbom:
            self.sbom["property"].append(property_entry)
        else:
            self.sbom["property"] = [property_entry]

    def get_sbom(self) -> SBOMData:
        return self.sbom

    def get_document(self) -> Dict:
        return self.sbom.get("document", {})

    def get_files(self) -> List:
        file_data = self.sbom.get("files", [])
        if len(file_data) > 0:
            return [x for x in self.sbom["files"].values()]
        return file_data

    def get_packages(self) -> List:
        package_data = self.sbom.get("packages", [])
        if len(package_data) > 0:
            return [x for x in self.sbom["packages"].values()]
        return package_data

    def get_relationships(self) -> List:
        return self.sbom.get("relationships", [])

    def get_vulnerabilities(self) -> Dict:
        return self.sbom.get("vulnerabilities", [])

    def get_services(self) -> Dict:
        return self.sbom.get("services", [])

    def get_licenses(self) -> List:
        return self.sbom.get("licenses", [])

    def get_version(self) -> str:
        return self.sbom.get("version", "")

    def get_type(self) -> str:
        return self.sbom.get("type", "")

    def get_uuid(self):
        return self.sbom.get("uuid", None)

    def get_bom_version(self):
        return self.sbom.get("bom_version", None)
