# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import re
import uuid
from datetime import datetime

from lib4sbom.data.vulnerability import Vulnerability
from lib4sbom.license import LicenseScanner
from lib4sbom.version import VERSION


class CycloneDXGenerator:
    """
    Generate CycloneDX SBOM.
    """

    CYCLONEDX_VERSION = "1.6"
    DATA_LICENCE = "CC0-1.0"
    PROJECT_ID = "CDXRef-DOCUMENT"
    PACKAGE_PREAMBLE = "CDXRef-Package-"
    LICENSE_PREAMBLE = "LicenseRef-"

    def __init__(
        self,
        cyclonedx_format="json",
        application="lib4sbom",
        version=VERSION,
    ):
        self.doc = []
        self.package_id = 0
        self.license = LicenseScanner()
        self.format = cyclonedx_format
        self.application = application
        self.application_version = version
        if self.format == "xml":
            self.doc = []
        else:
            self.doc = {}
            self.component = []
        self.relationship = []
        self.vulnerability = []
        self.service = []
        self.sbom_complete = False
        self.include_purl = False
        # Can specify version of CycloneDX through environment variable
        self.cyclonedx_version = os.getenv("LIB4SBOM_CYCLONEDX_VERSION")
        # Check valid version
        self.spec_version(self.cyclonedx_version)
        if self.cyclonedx_version is None:
            self.cyclonedx_version = self.CYCLONEDX_VERSION

    def store(self, message):
        self.doc.append(message)

    def getBOM(self):
        if not self.sbom_complete:
            if self.format == "xml":
                self.store("</components>")
                # Now process dependencies
                self.store("<dependencies>")
                for element in self.relationship:
                    item = element["ref"]
                    self.store(f'<dependency ref="{item}">')
                    for depends in element["dependsOn"]:
                        self.store(f'<dependency ref="{depends}"/>')
                    self.store("</dependency>")
                self.store("</dependencies>")
                self.store("</bom>")
            else:
                # Add set of detected components to SBOM
                if len(self.component) > 0:
                    self.doc["components"] = self.component
                if len(self.relationship) > 0:
                    self.doc["dependencies"] = self.relationship
                if len(self.vulnerability) > 0:
                    self.doc["vulnerabilities"] = self.vulnerability
                if len(self.service) > 0:
                    self.doc["services"] = self.service
            self.sbom_complete = True
        return self.doc

    def generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def spec_version(self, version):
        if version in ["1.3", "1.4", "1.5", "1.6"]:
            self.cyclonedx_version = version
        else:
            self.cyclonedx_version = None

    def _cyclonedx_15(self):
        # utility for features introduced in version 1.5
        return self.cyclonedx_version in ["1.5", "1.6"]

    def _cyclonedx_16(self):
        # utility for features introduced in version 1.6
        return self.cyclonedx_version in ["1.6"]

    def generateDocumentHeader(
        self, project_name, component_type, uuid=None, bom_version="1", property = None
    ):
        # Assume a new document being created
        self.relationship = []
        self.sbom_complete = False
        if self.format == "xml":
            self.doc = []
            return self.generateXMLDocumentHeader(project_name, uuid)
        else:
            self.doc = {}
            self.component = []
            return self.generateJSONDocumentHeader(
                project_name, component_type, uuid, bom_version, property)

    def _generate_urn(self):
        return "urn:uuid:" + str(uuid.uuid4())

    def generateJSONDocumentHeader(
        self, project_name, component_type, uuid=None, bom_version="1", property = None
    ):
        if uuid is None:
            urn = self._generate_urn()
        else:
            urn = uuid
        project_id = self.PROJECT_ID
        self.doc = {}
        self.doc[
            "$schema"
        ] = f"http://cyclonedx.org/schema/bom-{self.cyclonedx_version}.schema.json"
        self.doc["bomFormat"] = "CycloneDX"
        self.doc["specVersion"] = self.cyclonedx_version
        self.doc["serialNumber"] = urn
        self.doc["version"] = int(bom_version)
        metadata = {}
        if component_type["timestamp"] is None:
            metadata["timestamp"] = self.generateTime()
        else:
            metadata["timestamp"] = component_type["timestamp"]
        if component_type.get("lifecycle") is not None:
            # Validate lifecycle phase
            if component_type["lifecycle"].lower() in ["design","pre-build","build","post-build","operations","discovery","decommission"]:
                lifecycle = {}
                lifecycle["phase"] = component_type["lifecycle"].lower()
                metadata["lifecycles"] = [lifecycle]
        tool = {}
        author = {}
        if component_type["creator"] is not None:
            for creator in component_type["creator"]:
                type, param = creator
                if "#" in param:
                    if type == "tool":
                        tool["name"] = param.split("#")[0]
                        tool["version"] = param.split("#")[1]
                    elif type == "person":
                        author["name"] = param.split("#")[0]
                        author["email"] = param.split("#")[1]
        if len(tool) == 0:
            tool["name"] = self.application
            tool["version"] = self.application_version
        # Tools format changed in version 1.5
        if self._cyclonedx_15():
            tools = {}
            tool["type"] = "application"
            components = []
            components.append(tool)
            tools["components"] = components
        else:
            tools = []
            tools.append(tool)
        metadata["tools"] = tools
        if len(author) > 0:
            metadata["authors"] = [author]
        component = {}
        component["type"] = component_type["type"]
        if component_type["supplier"] is not None:
            supplier = {}
            supplier["name"] = component_type["supplier"]
            component["supplier"] = supplier
        if component_type["version"] is not None:
            component["version"] = component_type["version"]
        if component_type["bom-ref"] is not None:
            component["bom-ref"] = component_type["bom-ref"]
        else:
            component["bom-ref"] = project_id
        component["name"] = project_name
        if property is not None:
            metadata_property=[]
            for p in property:
                property_entry = dict()
                property_entry["name"] = p[0]
                property_entry["value"] = p[1]
                metadata_property.append(property_entry)
            metadata["properties"]=metadata_property
        metadata["component"] = component
        self.doc["metadata"] = metadata
        return component["bom-ref"]

    def generateXMLDocumentHeader(self, project_name, uuid=None):
        if uuid is None:
            urn = self._generate_urn()
        else:
            urn = uuid
        project_id = self.PROJECT_ID
        self.store("<?xml version='1.0' encoding='UTF-8'?>")
        self.store("<bom xmlns='http://cyclonedx.org/schema/bom/1.4'")
        self.store(f'serialNumber="{urn}"')
        self.store('version="1">')
        self.store("<metadata>")
        self.store(f"<timestamp>{self.generateTime()}</timestamp>")
        self.store("<tools>")
        self.store(f"<name>{self.application}</name>")
        self.store(f"<version>{self.application_version}</version>")
        self.store("</tools>")
        self.store(f"<component type='application' bom-ref='{project_id}'>")
        self.store(f"<name>{project_name}</name>")
        self.store("</component>")
        self.store("</metadata>")
        self.store("<components>")
        return project_id

    def generateRelationship(self, parent_id, package_id):
        # Check we have valid ids
        if parent_id is None or package_id is None:
            return
        # Avoid self->self relationship
        if parent_id == package_id:
            return
        # Check if entry exists. If so, update list of dependencies
        element_found = False
        for element in self.relationship:
            if element["ref"] == parent_id:
                element_found = True
                # Update list of dependencies if necessary
                if package_id not in element["dependsOn"]:
                    element["dependsOn"].append(package_id)
                    break
        if not element_found:
            # New item found
            dependency = dict()
            dependency["ref"] = parent_id
            dependency["dependsOn"] = [package_id]
            self.relationship.append(dependency)

    def generateComponent(self, id, type, package):
        if self.format == "xml":
            self.generateXMLComponent(id, type, package)
        else:
            self.generateJSONComponent(id, type, package)

    def _process_supplier_info(self, supplier_info):
        # Get email addresses
        # Use RFC-5322 compliant regex (https://regex101.com/library/6EL6YF)
        emails = re.findall(
            r"((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))",
            supplier_info,
        )
        # If email found, remove from string
        supplier_name = (
            supplier_info.replace(emails[-1], "") if len(emails) > 0 else supplier_info
        )
        # Get names
        names = re.findall(r"[a-zA-Z0-9\.\-]+[ A-Za-z0-9]*", supplier_name)
        supplier = " ".join(n for n in names)
        email_address = emails[-1] if len(emails) > 0 else ""
        return supplier.strip(), email_address

    def _governance_element(self, attribute):
        element_property = []
        for element in attribute:
            element_entry = {}
            if "organization" in element:
                item = {}
                item["name"] = element["organization"]
                element_entry["organization"] = item
            if "contact" in element:
                item = {}
                item["email"] = element["contact"]
                element_entry["contact"] = item
            element_property.append(element_entry)
        return element_property

    def _generate_mlmodel(self, package, id):
        ml_model = {}
        ml_model["bom-ref"] = f"{id}-model"
        if "modelcard" in package:
            # We have model card data!
            modelcard = package["modelcard"]
            ml_parameters = {}
            if "learning_type" in modelcard:
                ml_type = {}
                ml_type["type"] = modelcard["learning_type"]
                ml_parameters["approach"] = ml_type
            if "task" in modelcard:
                ml_parameters["task"] = modelcard["task"]
            if "architecture" in modelcard:
                ml_parameters["architectureFamily"] = modelcard["architecture"]
            if "model" in modelcard:
                ml_parameters["modelArchitecture"] = modelcard["model"]
            # Dataset
            if "dataset" in modelcard:
                ml_dataset = []
                for dataset in modelcard["dataset"]:
                    elements = {}
                    elements["type"] = dataset["dataset_type"]
                    if "name" in dataset:
                        elements["name"] = dataset["name"]
                    # contents
                    content = {}
                    if "content" in dataset:
                        attachment = {}
                        attachment["contentType"] = dataset["content_type"]
                        attachment["encoding"] = dataset["encoding"]
                        attachment["content"] = dataset["content"]
                        content["attachment"] = attachment
                    if "url" in dataset:
                        content["url"] = dataset["url"]
                    if "property" in dataset:
                        content_property = []
                        for property in dataset["property"]:
                            property_entry = dict()
                            property_entry["name"] = property[0]
                            property_entry["value"] = property[1]
                            content_property.append(property_entry)
                        content["properties"] = content_property
                    if len(content) > 0:
                        elements["contents"] = content
                    if "classification" in dataset:
                        elements["classification"] = dataset["classification"]
                    if "sensitive_data" in dataset:
                        elements["sensitiveData"] = dataset["sensitive_data"]
                    if "graphics" in dataset:
                        graphics = {}
                        graphics["description"] = dataset["graphics"]["description"]
                        graphics["collection"] = []
                        for element in dataset["graphics"]["collection"]:
                            graphic_entry = dict()
                            graphic_entry["name"] = element[0]
                            image = {}
                            image["contentType"] = "text/plain"
                            image["encoding"] = "base64"
                            image["content"] = element[1]
                            graphic_entry["image"] = image
                            graphics["collection"].append(graphic_entry)
                        elements["graphics"] = graphics
                    if "description" in dataset:
                        elements["description"] = dataset["description"]
                    governance = {}
                    if "custodian" in dataset:
                        governance["custodians"] = self._governance_element(
                            dataset["custodian"]
                        )
                    if "steward" in dataset:
                        governance["stewards"] = self._governance_element(
                            dataset["steward"]
                        )
                    if "owner" in dataset:
                        governance["owners"] = self._governance_element(
                            dataset["owner"]
                        )
                    if len(governance) > 0:
                        elements["governance"] = governance
                    ml_dataset.append(elements)
                ml_parameters["datasets"] = ml_dataset
            if "inputs" in modelcard:
                input_type = []
                for input in modelcard["inputs"]:
                    element = {}
                    element["format"] = input
                    input_type.append(element)
                ml_parameters["inputs"] = input_type
            if "outputs" in modelcard:
                output_type = []
                for output in modelcard["outputs"]:
                    element = {}
                    element["format"] = output
                    output_type.append(element)
                ml_parameters["outputs"] = output_type
            if len(ml_parameters) > 0:
                ml_model["modelParameters"] = ml_parameters
            # Quantitative Analysis
            quantitative = {}
            if "performance" in modelcard:
                performance_property = []
                for metric in modelcard["performance"]:
                    metric_entry = dict()
                    metric_entry["type"] = metric[0]
                    metric_entry["value"] = metric[1]
                    if len(metric[2]) > 0:
                        metric_entry["slice"] = metric[2]
                    interval = {}
                    interval["lowerBound"] = metric[3]
                    interval["upperBound"] = metric[4]
                    metric_entry["confidenceInterval"] = interval
                    performance_property.append(metric_entry)
                quantitative["performanceMetrics"] = performance_property
            if "graphics" in modelcard:
                graphics = {}
                graphics["description"] = modelcard["graphics"]["description"]
                graphics["collection"] = []
                for element in modelcard["graphics"]["collection"]:
                    graphic_entry = dict()
                    graphic_entry["name"] = element[0]
                    image = {}
                    image["contentType"] = "text/plain"
                    image["encoding"] = "base64"
                    image["content"] = element[1]
                    graphic_entry["image"] = image
                    graphics["collection"].append(graphic_entry)
                quantitative["graphics"] = graphics
            if len(quantitative) > 0:
                ml_model["quantitativeAnalysis"] = quantitative
            # Considerations
            considerations = {}
            if "user" in modelcard:
                user_property = []
                for user in modelcard["user"]:
                    user_property.append(user)
                considerations["users"] = user_property
            if "usecase" in modelcard:
                usecase_property = []
                for usecase in modelcard["usecase"]:
                    usecase_property.append(usecase)
                considerations["useCases"] = usecase_property
            if "limitation" in modelcard:
                limitation_property = []
                for limitation in modelcard["limitation"]:
                    limitation_property.append(limitation)
                considerations["technicalLimitations"] = limitation_property
            if "tradeoff" in modelcard:
                tradeoff_property = []
                for tradeoff in modelcard["tradeoff"]:
                    tradeoff_property.append(tradeoff)
                considerations["performanceTradeoffs"] = tradeoff_property
            if "ethicalrisk" in modelcard:
                ethicalrisk_property = []
                for risk in modelcard["ethicalrisk"]:
                    risk_entry = dict()
                    risk_entry["name"] = risk[0]
                    risk_entry["mitigationStrategy"] = risk[1]
                    ethicalrisk_property.append(risk_entry)
                considerations["ethicalConsiderations"] = ethicalrisk_property
            if "fairness" in modelcard:
                fairness_property = []
                for risk in modelcard["fairness"]:
                    risk_entry = dict()
                    risk_entry["groupAtRisk"] = risk[0]
                    risk_entry["benefits"] = risk[1]
                    risk_entry["harms"] = risk[2]
                    risk_entry["mitigationStrategy"] = risk[3]
                    fairness_property.append(risk_entry)
                considerations["fairnessAssessments"] = fairness_property
            if len(considerations) > 0:
                ml_model["considerations"] = considerations
            # Properties
            if "property" in modelcard:
                ml_properties = []
                for property in modelcard["property"]:
                    property_entry = dict()
                    property_entry["name"] = property[0]
                    property_entry["value"] = property[1]
                    if "properties" in ml_properties:
                        ml_properties.append(property_entry)
                    else:
                        ml_properties = [property_entry]
                ml_model["properties"] = ml_properties
        return ml_model

    def generateJSONComponent(self, id, type, package):
        component = dict()
        if "type" in package:
            component["type"] = package["type"].lower()
        else:
            component["type"] = type.lower()
        if package.get("bom-ref") is None:
            component["bom-ref"] = id
        else:
            component["bom-ref"] = package.get("bom-ref")
        # Crypto asset only for 1.6
        if component["type"] == "cryptographic-asset" and not self._cyclonedx_16():
            return
        name = package["name"]
        component["name"] = name
        if "version" in package:
            version = package["version"]
            component["version"] = version
        if "supplier" in package:
            # If email address in supplier, separate from name
            supplier_name, supplier_email = self._process_supplier_info(
                package["supplier"]
            )
            # Depends on supplier type
            if package["supplier_type"] != "UNKNOWN":
                # Either a person or organisation
                supplier = dict()
                supplier["name"] = supplier_name
                if len(supplier_email) > 0:
                    contact = dict()
                    contact["email"] = supplier_email
                    supplier["contact"] = [contact]
                component["supplier"] = supplier
                # Not for machine learning model
                if component["type"] != "machine-learning-model":
                    if "version" in package:
                        if component["type"] == "operating-system":
                            cpe_type = "/o"
                        else:
                            cpe_type = "/a"
                        component[
                            "cpe"
                        ] = f'cpe:{cpe_type}:{supplier_name.replace(" ", "_")}:{name}:{version}'
                # Alternative is it within external reference
        if "originator" in package:
            component["author"] = package["originator"]
        if "description" in package:
            component["description"] = package["description"]
        elif "summary" in package:
            component["description"] = package["summary"]
        if "checksum" in package:
            for checksum in package["checksum"]:
                checksum_entry = dict()
                checksum_entry["alg"] = checksum[0].replace("SHA", "SHA-")
                checksum_entry["content"] = checksum[1]
                if "hashes" in component:
                    component["hashes"].append(checksum_entry)
                else:
                    component["hashes"] = [checksum_entry]
        if "licenselist" in package:
            # Multiple licenses declared for component
            licenses = []
            for license in package["licenselist"]:
                licenses.append(license)
            component["licenses"] = licenses
        elif "licenseconcluded" in package or "licensedeclared" in package:
            if "licenseconcluded" in package:
                license_definition = package["licenseconcluded"]
                acknowledgement = "concluded"
            else:
                license_definition = package["licensedeclared"]
                acknowledgement = "declared"
            license_id = self.license.find_license(license_definition)
            if license_id not in ["UNKNOWN", "NOASSERTION", "NONE"]:
                # A valid SPDX license
                license = dict()
                # SPDX license expression handled separately to single license
                if self.license.license_expression(license_id):
                    license["expression"] = license_id
                    component["licenses"] = [license]
                else:
                    license["id"] = license_id
                    license_url = self.license.get_license_url(license["id"])
                    if license_url is not None:
                        license["url"] = license_url
                    if self._cyclonedx_16():
                        license["acknowledgement"] = acknowledgement
                    item = dict()
                    item["license"] = license
                    component["licenses"] = [item]
            elif license_definition not in ["UNKNOWN", "NOASSERTION", "NONE"]:
                # Not a valid SPDX license
                license = dict()
                if "licensename" in package:
                    license["name"] = package["licensename"]
                    text = {}
                    text["content"] = license_definition
                    license["text"] = text
                else:
                    license["name"] = license_definition
                item = dict()
                item["license"] = license
                component["licenses"] = [item]
        if "copyrighttext" in package:
            if package["copyrighttext"] != "NOASSERTION":
                component["copyright"] = package["copyrighttext"]
        if "homepage" in package:
            externalReference = dict()
            externalReference["url"] = package["homepage"]
            externalReference["type"] = "website"
            externalReference["comment"] = "Home page for project"
            component["externalReferences"] = [externalReference]
        if "downloadlocation" in package:
            externalReference = dict()
            externalReference["url"] = package["downloadlocation"]
            externalReference["type"] = "distribution"
            externalReference["comment"] = "Download location for component"
            if "externalReferences" in component:
                component["externalReferences"].append(externalReference)
            else:
                component["externalReferences"] = [externalReference]
        if "group" in package:
            component["group"] = package["group"]
        if "evidence" in package:
            occurrences = []
            evidence_info = {}
            for evidence in package["evidence"]:
                occurrences.append({"location": evidence})
            evidence_info["occurrences"] = occurrences
            component["evidence"] = evidence_info
        if "externalreference" in package:
            # Potentially multiple entries
            for reference in package["externalreference"]:
                ref_category = reference[0]
                ref_type = reference[1]
                ref_value = reference[2]
                if ref_category == "SECURITY" and ref_type in [
                    "cpe22Type",
                    "cpe23Type",
                ]:
                    component["cpe"] = ref_value
                elif (
                    ref_category in ["PACKAGE-MANAGER", "PACKAGE_MANAGER"]
                    and ref_type == "purl"
                ):
                    component["purl"] = ref_value
                else:
                    externalReference = dict()
                    externalReference["url"] = ref_value
                    externalReference["type"] = ref_type
                    #externalReference["comment"] = ref_category
                    if "externalReferences" in component:
                        component["externalReferences"].append(externalReference)
                    else:
                        component["externalReferences"] = [externalReference]
        if "property" in package:
            for property in package["property"]:
                property_entry = dict()
                property_entry["name"] = property[0]
                property_entry["value"] = property[1]
                if "properties" in component:
                    component["properties"].append(property_entry)
                else:
                    component["properties"] = [property_entry]
        # SPDX items with no corresponding entry are created as properties
        if "licensecomment" in package:
            property_entry = dict()
            property_entry["name"] = "License Comments"
            property_entry["value"] = package["licensecomment"]
            if "properties" in component:
                component["properties"].append(property_entry)
            else:
                component["properties"] = [property_entry]
        if "comment" in package:
            property_entry = dict()
            property_entry["name"] = "Comment"
            property_entry["value"] = package["comment"]
            if "properties" in component:
                component["properties"].append(property_entry)
            else:
                component["properties"] = [property_entry]
        if self._cyclonedx_15() and component["type"] == "machine-learning-model":
            # Only for version 1.5 or later
            component["modelCard"] = self._generate_mlmodel(
                package, component["bom-ref"]
            )
        self.component.append(component)

    def generateXMLComponent(self, id, type, package):
        self.store(f'<component type="{type}" bom-ref="{id}">')
        name = package["name"]
        version = package["version"]
        self.store(f"<name>{name}</name>")
        self.store(f"<version>{version}</version>")
        if "supplier" in package:
            # Supplier name mustn't have spaces in. Covert spaces to '_'
            self.store(
                f'<cpe>cpe:/a:{package["supplier"].replace(" ", "_")}:{name}:{version}</cpe>'
            )
        if "licenseconcluded" in package:
            license_id = self.license.find_license(package["licenseconcluded"])
            # Only include if valid license
            if license_id not in ["UNKNOWN", "NOASSERTION"]:
                self.store("<licenses>")
                self.store("<license>")
                self.store(f'<id>"{license_id}"</id>')
                license_url = self.license.get_license_url(license_id)
                if license_url is not None:
                    self.store(f'<url>"{license_url}"</url>')
                self.store("</license>")
                self.store("</licenses>")
        if "externalreference" in package:
            # Potentially multiple entries
            for reference in package["externalreference"]:
                ref_category = reference[0]
                ref_type = reference[1]
                ref_value = reference[2]
                if ref_category == "SECURITY" and ref_type in [
                    "cpe22Type",
                    "cpe23Type",
                ]:
                    self.store(f"<cpe>{ref_value}</cpe>")
                if (
                    ref_category in ["PACKAGE-MANAGER", "PACKAGE_MANAGER"]
                    and ref_type == "purl"
                ):
                    self.store(f"<purl>{ref_value}</purl>")
        self.store("</component>")

    def generate_vulnerability_data(self, vulnerabilities):
        statements = []
        for vuln in vulnerabilities:
            vulnerability = {}
            vuln_info = Vulnerability(validation="cyclonedx")
            vuln_info.copy_vulnerability(vuln)
            if "bom-ref" in vuln:
                vulnerability["bom-ref"] = vuln_info.get_value("bom-ref")
            else:
                # Assume ref is based on product
                if "release" in vuln:
                    vulnerability[
                        "bom-ref"
                    ] = f'{vuln_info.get_value("product")}@{vuln_info.get_value("release")}'
                else:
                    # assume it is a PURL
                    vulnerability["bom-ref"] = vuln_info.get_value("purl")
            vulnerability["id"] = vuln_info.get_value("id")
            if vulnerability["id"].startswith("CVE-"):
                # NVD Data source
                source = {}
                source["name"] = "NVD"
                source[
                    "url"
                ] = f"https://nvd.nist.gov/vuln/detail/{vulnerability['id']}"
                vulnerability["source"] = source
            if "description" in vuln:
                vulnerability["description"] = vuln_info.get_value("description")
            if "created" in vuln:
                vulnerability["published"] = vuln_info.get_value("created")
            else:
                vulnerability["published"] = self.doc["metadata"]["timestamp"]
            vulnerability["updated"] = self.doc["metadata"]["timestamp"]
            analysis = {}
            analysis["state"] = vuln_info.get_value("status")
            if analysis["state"] is None or not vuln_info.validate_status(
                analysis["state"]
            ):
                analysis["state"] = "in_triage"
            if "comment" in vuln:
                analysis["detail"] = vuln_info.get_value("comment")
            if "justification" in vuln:
                analysis["justification"] = vuln_info.get_value("justification")
            if "remediation" in vuln:
                analysis["response"] = []
                analysis["response"].append(vuln_info.get_value("remediation"))
                analysis["detail"] = vuln_info.get_value("action")
            vulnerability["analysis"] = analysis
            if "bom_link" in vuln:
                affects = []
                affected = {}
                affected["ref"] = vuln_info.get_value("bom_link")
                version_info = {}
                component_version = vuln_info.get_value("release")
                if component_version is None and vuln_info.get_value("purl") is not None:
                    # Could be a PURL - just extract version of component
                    component_version = vuln_info.get_value("purl").split("@")[1]
                if analysis["state"] in ["not_affected","false_positive"]:
                    version_info["version"] = component_version
                    version_info["status"] = "unaffected"
                elif analysis["state"] != "in_triage":
                    version_info["version"] = component_version
                    version_info["status"] = "affected"
                if len(version_info) > 0:
                    affected["versions"] = version_info
                affects.append(affected)
                vulnerability["affects"] = affects
            statements.append(vulnerability)
        self.vulnerability = statements

    def generate_service_data(self, services):
        service_definitions = []
        service_number = 1
        sbom_services = [x for x in services.values()]
        for serv in sbom_services:
            service = {}
            if "id" in serv:
                service["bom-ref"] = serv["id"]
            else:
                service["bom-ref"] = f"Service-{service_number}"
            service["name"] = serv["name"]
            if "version" in serv:
                service["version"] = serv["version"]
            if "description" in serv:
                service["description"] = serv["description"]
            if "provider" in serv:
                provider = {}
                if "name" in serv["provider"]:
                    provider["name"] = serv["provider"]["name"]
                if "url" in serv["provider"]:
                    provider["url"] = serv["provider"]["url"]
                contact = {}
                if "contact" in serv["provider"]:
                    contact["name"] = serv["provider"]["contact"]
                if "email" in serv["provider"]:
                    contact["email"] = serv["provider"]["email"]
                if "phone" in serv["provider"]:
                    contact["email"] = serv["provider"]["phone"]
                if len(contact) > 0:
                    provider["contact"] = contact
                service["provider"] = provider
            if "endpoints" in serv:
                service["endpoints"] = serv["endpoints"]
            if "authenticated" in serv:
                service["authenticated"] = serv["authenticated"]
            if "x-trust-boundary" in serv:
                service["x-trust-boundary"] = serv["x-trust-boundary"]
            if "trustZone" in serv:
                service["trustZone"] = serv["trustZone"]
            if "data" in serv:
                data = []
                for data_item in serv["data"]:
                    data_element = {}
                    data_element["flow"] = data_item.get("flow")
                    data_element["classification"] = data_item.get("classification")
                    if "name" in data_item:
                        data_element["name"] = data_item.get("name")
                    if "description" in data_item:
                        data_element["description"] = data_item.get("description")
                    data.append(data_element)
                service["data"] = data
            if "licenseinfo" in serv:
                licenses = []
                for license_item in serv["licenseinfo"]:
                    licenses.append({"license": license_item})
                service["licenses"] = licenses
            if "property" in serv:
                for property in serv["property"]:
                    property_entry = dict()
                    property_entry["name"] = property[0]
                    property_entry["value"] = property[1]
                    if "properties" in service:
                        service["properties"].append(property_entry)
                    else:
                        service["properties"] = [property_entry]
            if "externalreference" in serv:
                # Potentially multiple entries
                for reference in serv["externalreference"]:
                    url = reference[0]
                    ref_type = reference[1]
                    ref_comment = reference[2]
                    externalReference = dict()
                    externalReference["url"] = url
                    externalReference["type"] = ref_type
                    if len(ref_comment) > 0:
                        externalReference["comment"] = ref_comment
                    if "externalReferences" in service:
                        service["externalReferences"].append(externalReference)
                    else:
                        service["externalReferences"] = [externalReference]
            service_definitions.append(service)
            service_number += 1
        self.service = service_definitions
