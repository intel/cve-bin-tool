# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import re

import semantic_version

from lib4sbom.cyclonedx.cyclonedx_generator import CycloneDXGenerator
from lib4sbom.data.document import SBOMDocument
from lib4sbom.output import SBOMOutput
from lib4sbom.sbom import SBOMData
from lib4sbom.spdx.spdx_generator import SPDXGenerator
from lib4sbom.version import VERSION


class SBOMGenerator:
    """
    Simple SBOM Generator.
    """

    def __init__(
        self,
        validate_license: bool = True,
        sbom_type: str = "spdx",
        format: str = "tag",
        application: str = "lib4sbom",
        version: str = VERSION,
    ):
        self.format = format.lower()
        self.sbom_type = sbom_type.lower()
        # Ensure specified format is supported
        if self.format not in ["tag", "json", "yaml"]:
            # Set a default format
            self.format = "json"
        if self.sbom_type not in ["spdx", "cyclonedx"]:
            # Set a default SBOM type
            self.sbom_type = "spdx"
        # Ensure format is compatible with SBOM type
        if self.sbom_type == "cyclonedx":
            # Tag and YAML not valid for CycloneDX
            if self.format in ["tag", "yaml"]:
                self.format = "json"

        if self.sbom_type == "spdx":
            self.bom = SPDXGenerator(
                validate_license, self.format, application, version
            )
        else:
            self.bom = CycloneDXGenerator(self.format, application, version)
        self.sbom_complete = False
        self.element_set = {}
        self.sbom = None
        self.debug = os.getenv("LIB4SBOM_DEBUG") is not None

    def get_format(self) -> str:
        return self.format

    def get_type(self) -> str:
        return self.sbom_type

    def get_sbom(self):
        return self.sbom

    def generate(
        self,
        project_name: str,
        sbom_data: SBOMData,
        filename: str = "",
        send_to_output: bool = True,
    ) -> None:
        if len(sbom_data) > 0:
            self.element_set = {}
            if project_name == "":
                if self.debug:
                    print("[ERROR] Project name missing")
                project_name = "Default_project"
            if self.sbom_type == "spdx":
                self._generate_spdx(project_name, sbom_data)
                self.sbom = self._get_spdx()
            else:
                self._generate_cyclonedx(project_name, sbom_data)
                self.sbom = self._get_cyclonedx()
            if send_to_output:
                sbom_out = SBOMOutput(filename, output_format=self.format)
                sbom_out.generate_output(self.sbom)

    def _validate_id(self, id):
        if id is None:
            return False
        return bool(re.match(r"^[\da-zA-Z.-]+$", id))

    def _generate_spdx(self, project_name: str, sbom_data: SBOMData) -> None:
        self.sbom_complete = False
        # Set spec version if explicitly specified
        if "version" in sbom_data:
            self.bom.spec_version(sbom_data["version"])
        if "uuid" in sbom_data:
            uuid = sbom_data["uuid"]
        else:
            uuid = None
        name = None
        if "document" in sbom_data:
            doc = SBOMDocument()
            doc.copy_document(sbom_data["document"])
            name = doc.get_name()
        if name is not None and name != "NOT DEFINED":
            # Use existing document name
            project_id = self.bom.generateDocumentHeader(name, uuid)
            self._save_element(name, project_id)
        else:
            project_id = self.bom.generateDocumentHeader(project_name, uuid)
            self._save_element(project_name, project_id)
        if "licenses" in sbom_data and len(sbom_data["licenses"]) > 0:
            # Load user defined licences
            self.bom.addLicenseDetails(sbom_data["licenses"])
        if "files" in sbom_data:
            # Process list of files
            if len(sbom_data["files"]) is not None:
                sbom_files = [x for x in sbom_data["files"].values()]
                id = 1
                relationship = "CONTAINS"
                for file in sbom_files:
                    file_id = file["id"]
                    if file_id == "NOT_DEFINED" or not self._validate_id(file_id):
                        file_id = str(id) + "-" + file["name"]
                    self.bom.generateFileDetails(
                        file["name"],
                        file_id,
                        file,
                        project_id,
                        relationship,
                    )
                    self._save_element(file["name"], file_id)
                    id = id + 1
        # Process list of packages
        if "packages" in sbom_data:
            id = 1
            sbom_packages = [x for x in sbom_data["packages"].values()]
            for package in sbom_packages:
                if "name" not in package:
                    if self.debug:
                        print(f"[ERROR] Name missing in {package}")
                    continue
                product = package["name"]
                my_id = package.get("id", None)
                if not self._validate_id(my_id):
                    my_id = f"{id}-{product}"
                parent = "-"
                self._save_element(product, my_id, my_id)
                if parent == "-":
                    parent_id = project_id
                    relationship = "DESCRIBES"
                else:
                    if parent in self.element_set:
                        parent_id = self._get_element(parent)
                        relationship = "DEPENDS_ON"
                self.bom.generatePackageDetails(
                    product,
                    my_id,
                    package,
                    parent_id,
                    relationship,
                )
                id = id + 1
        # If user defined licenses defined, generate details
        self.bom.generateLicenseDetails()
        if "relationships" in sbom_data:
            for relationship in sbom_data["relationships"]:
                if (
                    relationship["source"] in self.element_set
                    and relationship["target"] in self.element_set
                ):
                    source_ident = self.bom.package_ident(
                        self._get_element(
                            relationship["source"], relationship["source_id"]
                        )
                    )
                    if relationship.get("target_type") == "file":
                        target_ident = self.bom.file_ident(
                            self._get_element(
                                relationship["target"], relationship["target_id"]
                            )
                        )
                    else:
                        target_ident = self.bom.package_ident(
                            self._get_element(
                                relationship["target"], relationship["target_id"]
                            )
                        )

                    self.bom.generateRelationship(
                        source_ident,
                        target_ident,
                        " " + relationship["type"] + " ",
                    )
                elif self.debug:
                    print(
                        "[ERROR] Relationship not copied between",
                        relationship["source"],
                        " and ",
                        relationship["target"],
                    )

    def _get_spdx(self):
        if not self.sbom_complete:
            self.bom.showRelationship()
            self.sbom_complete = True
        return self.bom.getBOM()

    def _get_relationships(self):
        return self.bom.getRelationships()

    def _get_cyclonedx(self):
        return self.bom.getBOM()

    def _save_element(self, name, id, id2=None):
        if name not in self.element_set:
            self.element_set[name] = [(id, id2)]
        else:
            # Duplicated name
            self.element_set[name].append((id, id2))

    def _semantic_version(self, version):
        # Semantic version requires at least major.minor.patch.
        # Add any component parts which are missing
        if version.count(".") > 1:
            version_spec = version
        elif version.count(".") == 1:
            version_spec = version + ".0"
        else:
            version_spec = version + ".0.0"
        try:
            sem_version = semantic_version.Version(version_spec)
        except ValueError:
            # Version string does not follow semantic version specification
            sem_version = version_spec
        return sem_version

    def _get_element(self, name, id=None):
        default_version = semantic_version.Version("0.0.0")
        check = self.element_set.get(name)
        if check is not None:
            if len(check) > 1:
                # Duplicate name identified. Match against id
                # If no version specified, select component with the latest
                # version based on semantic version ordering
                # Each element entry is <package id> <version id of form name_version>
                latest_version = default_version
                if id is None and check[0][1] is not None:
                    latest_version = self._semantic_version(check[0][1].split("_")[-1])
                index = i = 0
                for c in check:
                    if id is None:
                        current_version = default_version
                        if c[1] is not None:
                            current_version = self._semantic_version(
                                c[1].split("_")[-1]
                            )
                        if current_version > latest_version:
                            latest_version = current_version
                            index = i
                    elif c[1] == id:
                        return c[0]
                    i += 1
                return check[index][0]
            else:
                # Could be two elements
                if check[0][1] == id:
                    if id is None:
                        return check[0][0]
                    return check[0][1]
                return check[0][0]
        return check

    def _generate_cyclonedx(self, project_name: str, sbom_data: SBOMData) -> None:
        # Set spec version if explicitly specified
        if "version" in sbom_data:
            self.bom.spec_version(sbom_data["version"])
        if "uuid" in sbom_data:
            uuid = sbom_data["uuid"]
        else:
            uuid = None
        name = None

        if "bom_version" in sbom_data:
            bom_version = sbom_data["bom_version"]
        else:
            bom_version = "1"
        if "property" in sbom_data:
            property = sbom_data["property"]
        else:
            property = None
        component_data = {
            "type": "application",
            "supplier": None,
            "version": None,
            "bom-ref": None,
            "timestamp": None,
            "creator": None,
            "lifecycle": None,
        }
        if "document" in sbom_data:
            doc = SBOMDocument()
            doc.copy_document(sbom_data["document"])
            name = doc.get_name()
            component_data["type"] = doc.get_value("metadata_type", "application")
            component_data["supplier"] = doc.get_value("metadata_supplier")
            component_data["version"] = doc.get_value("metadata_version")
            component_data["bom-ref"] = doc.get_value("bom-ref")
            component_data["lifecycle"] = doc.get_value("lifecycle")
            component_data["timestamp"] = doc.get_created()
            component_data["creator"] = doc.get_creator()
        if name is not None and name != "NOT DEFINED":
            # Use existing document name
            project_id = self.bom.generateDocumentHeader(
                name, component_data, uuid, bom_version, property
            )
            self._save_element(name, project_id)
        else:
            project_id = self.bom.generateDocumentHeader(
                project_name, component_data, uuid, bom_version, property
            )
            self._save_element(project_name, project_id)
        parent = project_name
        if "licenses" in sbom_data and len(sbom_data["licenses"]) > 0:
            # Load user defined licences
            print("User defined licences available")
        # Process list of files
        if "files" in sbom_data:
            # Process list of files
            if len(sbom_data["files"]) is not None:
                sbom_files = [x for x in sbom_data["files"].values()]
                id = 1
                for file in sbom_files:
                    my_id = file["id"]
                    if my_id == "NOT_DEFINED":
                        my_id = str(id) + "-" + file["name"]
                    self._save_element(file["name"], my_id)
                    self.bom.generateComponent(my_id, "file", file)
                    id = id + 1
        # Process list of packages
        if "packages" in sbom_data:
            id = 1
            sbom_packages = [x for x in sbom_data["packages"].values()]
            for package in sbom_packages:
                product = package["name"]
                my_id = package.get("bom-ref", None)
                if my_id is None:
                    my_id = package.get("id", None)
                    if not self._validate_id(my_id):
                        my_id = f"{id}-{product}"
                self._save_element(product, str(id) + "-" + product, my_id)
                if parent == "-":
                    type = "application"
                else:
                    type = "library"
                self.bom.generateComponent(
                    self._get_element(product, my_id), type, package
                )
                id = id + 1
        if "relationships" in sbom_data:
            for relationship in sbom_data["relationships"]:
                self.bom.generateRelationship(
                    self._get_element(
                        relationship["source"], relationship["source_id"]
                    ),
                    self._get_element(
                        relationship["target"], relationship["target_id"]
                    ),
                )
        if "vulnerabilities" in sbom_data:
            self.bom.generate_vulnerability_data(sbom_data["vulnerabilities"])
        if "services" in sbom_data:
            self.bom.generate_service_data(sbom_data["services"])


# End of file
