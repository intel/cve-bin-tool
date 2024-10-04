# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import json
import os
import uuid

import defusedxml.ElementTree as ET

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.modelcard import ModelDataset, ModelGraphicset, SBOMModelCard
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.data.service import SBOMService
from lib4sbom.data.vulnerability import Vulnerability


class CycloneDXParser:
    def __init__(self):
        self.debug = os.getenv("LIB4SBOM_DEBUG") is not None
        self.cyclonedx_package = SBOMPackage()
        self.packages = {}
        self.id = {}
        self.licences = []
        self.component_id = 0
        self.model_card = SBOMModelCard()
        self.cyclonedx_version = None

    def parse(self, sbom_file):
        """parses CycloneDX BOM file extracting package name, version and license"""
        if sbom_file.endswith((".bom.json", ".cdx.json", ".json")):
            return self.parse_cyclonedx_json(sbom_file)
        elif sbom_file.endswith((".bom.xml", ".cdx.xml", ".xml")):
            return self.parse_cyclonedx_xml(sbom_file)
        else:
            return {}, {}, {}, [], [], [], []

    def _governance_element(self, element):
        elements = []
        for item in element:
            entry = {}
            if "organization" in item:
                if "name" in item["organization"]:
                    entry["organization"] = item["organization"]["name"]
            if "contact" in item:
                if "email" in item["contact"]:
                    entry["contact"] = item["contact"]["email"]
            if len(entry) > 0:
                elements.append(entry)
        return elements

    def _cyclonedx_15(self):
        # utility for features introduced in version 1.5
        return self.cyclonedx_version in ["1.5", "1.6"]

    def _cyclonedx_16(self):
        # utility for features introduced in version 1.6
        return self.cyclonedx_version in ["1.6"]

    def _cyclonedx_mlmodel(self, d):
        # Machine learning model data
        self.model_card.initialise()
        if "bom-ref" in d["modelCard"]:
            self.model_card.set_id(d["modelCard"]["bom-ref"])
        if "modelParameters" in d["modelCard"]:
            if "approach" in d["modelCard"]["modelParameters"]:
                self.model_card.set_model_type(
                    d["modelCard"]["modelParameters"]["approach"]["type"]
                )
            if "task" in d["modelCard"]["modelParameters"]:
                self.model_card.set_task(d["modelCard"]["modelParameters"]["task"])
            if "architectureFamily" in d["modelCard"]["modelParameters"]:
                self.model_card.set_architecture(
                    d["modelCard"]["modelParameters"]["architectureFamily"]
                )
            if "modelArchitecture" in d["modelCard"]["modelParameters"]:
                self.model_card.set_model(
                    d["modelCard"]["modelParameters"]["modelArchitecture"]
                )
            if "datasets" in d["modelCard"]["modelParameters"]:
                for dataset in d["modelCard"]["modelParameters"]["datasets"]:
                    dataset_info = ModelDataset()
                    dataset_info.set_dataset_type(dataset["type"])
                    dataset_info.set_name(dataset["name"])
                    dataset_info.set_id(dataset.get("bom-ref"))
                    # Contents
                    if "contents" in dataset:
                        if "attachment" in dataset["contents"]:
                            dataset_info.set_contents(
                                dataset["contents"]["attachment"]["content"]
                            )
                        if "url" in dataset["contents"]:
                            dataset_info.set_contents(url=dataset["contents"]["url"])
                        if "properties" in dataset["contents"]:
                            for property in dataset["contents"]["properties"]:
                                dataset_info.set_content_property(
                                    property["name"], property["value"]
                                )
                    dataset_info.set_classification(dataset["classification"])
                    if "sensitiveData" in dataset:
                        dataset_info.set_sensitive_data(dataset["sensitiveData"])
                    # Graphics
                    if "graphics" in dataset:
                        graphicset = ModelGraphicset()
                        graphicset.set_description(dataset["graphics"]["description"])
                        for graphic in dataset["graphics"]["collection"]:
                            image = graphic["image"]
                            graphicset.add_image(
                                graphic.get("name"), image.get("content")
                            )
                        dataset_info.set_graphics(graphicset.get_graphicset())
                    if "description" in dataset:
                        dataset_info.set_description(dataset["description"])
                    # Governance
                    if "governance" in dataset:
                        if "custodians" in dataset["governance"]:
                            for entry in self._governance_element(
                                dataset["governance"]["custodians"]
                            ):
                                dataset_info.set_governance(custodian=entry)
                        if "stewards" in dataset["governance"]:
                            for entry in self._governance_element(
                                dataset["governance"]["stewards"]
                            ):
                                dataset_info.set_governance(steward=entry)
                        if "owners" in dataset["governance"]:
                            for entry in self._governance_element(
                                dataset["governance"]["owners"]
                            ):
                                dataset_info.set_governance(owner=entry)
                    self.model_card.set_dataset(dataset_info.get_dataset())
            if "inputs" in d["modelCard"]["modelParameters"]:
                for inputs in d["modelCard"]["modelParameters"]["inputs"]:
                    self.model_card.set_inputs(inputs["format"])
            if "outputs" in d["modelCard"]["modelParameters"]:
                for outputs in d["modelCard"]["modelParameters"]["outputs"]:
                    self.model_card.set_outputs(outputs["format"])
        if "quantitativeAnalysis" in d["modelCard"]:
            if "performanceMetrics" in d["modelCard"]["quantitativeAnalysis"]:
                for metric in d["modelCard"]["quantitativeAnalysis"][
                    "performanceMetrics"
                ]:
                    lowerbound = upperbound = None
                    if "confidenceInterval" in metric:
                        interval = metric["confidenceInterval"]
                        lowerbound = interval.get("lowerBound")
                        upperbound = interval.get("upperBound")
                    self.model_card.set_performance(
                        metric.get("type"),
                        metric.get("value"),
                        metric.get("slice"),
                        lowerbound,
                        upperbound,
                    )
            if "graphics" in d["modelCard"]["quantitativeAnalysis"]:
                graphicset = ModelGraphicset()
                graphicset.set_description(
                    d["modelCard"]["quantitativeAnalysis"]["graphics"]["description"]
                )
                for graphic in d["modelCard"]["quantitativeAnalysis"]["graphics"][
                    "collection"
                ]:
                    image = graphic["image"]
                    graphicset.add_image(graphic.get("name"), image.get("content"))
                self.model_card.set_graphics(graphicset.get_graphicset())
        if "considerations" in d["modelCard"]:
            if "users" in d["modelCard"]["considerations"]:
                for user in d["modelCard"]["considerations"]["users"]:
                    self.model_card.set_user(user)
            if "useCases" in d["modelCard"]["considerations"]:
                for usecase in d["modelCard"]["considerations"]["useCases"]:
                    self.model_card.set_usecase(usecase)
            if "technicalLimitations" in d["modelCard"]["considerations"]:
                for limitation in d["modelCard"]["considerations"][
                    "technicalLimitations"
                ]:
                    self.model_card.set_limitation(limitation)
            if "performanceTradeoffs" in d["modelCard"]["considerations"]:
                for tradeoff in d["modelCard"]["considerations"][
                    "performanceTradeoffs"
                ]:
                    self.model_card.set_tradeoff(tradeoff)
            if "ethicalConsiderations" in d["modelCard"]["considerations"]:
                for consideration in d["modelCard"]["considerations"][
                    "ethicalConsiderations"
                ]:
                    self.model_card.set_ethicalrisk(
                        consideration.get("name"),
                        consideration.get("mitigationStrategy"),
                    )
            if "fairnessAssessments" in d["modelCard"]["considerations"]:
                for assessment in d["modelCard"]["considerations"][
                    "fairnessAssessments"
                ]:
                    self.model_card.set_fairness(
                        assessment["groupAtRisk"],
                        assessment["benefits"],
                        assessment["harms"],
                        assessment["mitigationStrategy"],
                    )
        if "properties" in d["modelCard"]:
            # Potentially multiple entries
            for property in d["modelCard"]["properties"]:
                self.model_card.set_property(property["name"], property["value"])

    def process_license(self, license_element):
        license_info = []
        for l in license_element:
            if "license" in l:
                # Potentially multiple licenses
                # At least one of id or name must be specified
                id = name = None
                if "id" in l["license"]:
                    # A valid SPDX Id
                    id = l["license"]["id"]
                if "name" in l["license"]:
                    name = l["license"]["name"]
                if id is None and name is None:
                    print (f"[ERROR] Invalid license specified {l} - missing id or name.")
                else:
                    license_info.append(l["license"])
            else:
                # SPDX License expression - can only have one instance
                if len (license_info) > 0:
                    print (f"[ERROR] Invalid license specified {l}  - only one SPDX expression allowed.")
                else:
                    type = None
                    license = None
                    if "expression" in l:
                        license = l["expression"]
                    if "acknowledgement" in l:
                        type = l["acknowledgement"]
                    if license is None:
                        print(f"[ERROR] Invalid license specified {l}  - expression missing.")
                    else:
                        license_info.append({"expression": license, "acknowledgement": type})
        return license_info

    def _cyclondex_component(self, d):
        self.cyclonedx_package.initialise()
        self.component_id = self.component_id + 1
        if d["type"] in [
            "application",
            "framework",
            "library",
            "container",
            "platform",
            "operating-system",
            "device",
            "device-driver",
            "firmware",
            "file",
            "machine-learning-model",
            "data",
        ]:
            package = d["name"]
            self.cyclonedx_package.set_name(package)
            if "version" in d:
                version = d["version"]
                self.cyclonedx_package.set_version(version)
            else:
                if self.debug:
                    print(f"[ERROR] Version not specified for {package}")
                version = "MISSING"
            # Record type of component
            self.cyclonedx_package.set_type(d["type"])
            # If bom-ref not present, auto generate one
            bom_ref = d.get("bom-ref", f"CycloneDX-Component-{self.component_id}")
            self.cyclonedx_package.set_value("bom-ref", bom_ref)
            if "supplier" in d:
                # Assume that this refers to an organisation
                supplier_name = ""
                if "name" in d["supplier"]:
                    supplier_name = d["supplier"]["name"]
                elif "url" in d["supplier"]:
                    for u in d["supplier"]["url"]:
                        supplier_name = u
                # Check for contact details (email)
                if "contact" in d["supplier"]:
                    for contact in d["supplier"]["contact"]:
                        if "email" in contact:
                            supplier_name = f'{supplier_name} ({contact["email"]})'
                if len(supplier_name) > 0:
                    self.cyclonedx_package.set_supplier("Organisation", supplier_name)
            if "author" in d:
                # Assume that this refers to an individual
                self.cyclonedx_package.set_originator("Person", d["author"])
            if "description" in d:
                self.cyclonedx_package.set_description(d["description"])
            if "hashes" in d:
                # Potentially multiple entries
                for checksum in d["hashes"]:
                    self.cyclonedx_package.set_checksum(
                        checksum["alg"].replace("SHA-", "SHA"), checksum["content"]
                    )
            license_data = None
            # Multiple ways of defining license data
            if "licenses" in d:
                license_data = self.process_license(d["licenses"])
            elif "evidence" in d:
                license_data = self.process_license(d["evidence"])
            if license_data is not None and len(license_data) > 0:
                # Multiple ways of defining licenses
                for license_info in license_data:
                    license = license_info.get("expression")
                    if license is None:
                        license = license_info.get("id")
                        if license is None:
                            license = license_info.get("name")
                    acknowledgement = license_info.get("acknowledgement")
                    if license is not None:
                        # CycloneDX 1.6 distinguishes between concluded and declared
                        if self._cyclonedx_16():
                            if acknowledgement is not None:
                                if acknowledgement == "concluded":
                                    self.cyclonedx_package.set_licenseconcluded(license)
                                else:
                                    self.cyclonedx_package.set_licensedeclared(license)
                            else:
                                self.cyclonedx_package.set_licenseconcluded(license)
                                self.cyclonedx_package.set_licensedeclared(license)
                        else:
                            # Assume License concluded is same as license declared
                            self.cyclonedx_package.set_licenseconcluded(license)
                            self.cyclonedx_package.set_licensedeclared(license)
                if license_data is not None and len(license_data) > 1:
                    self.cyclonedx_package.set_licenselist(license_data)
            # acknowledgement = None
            # multi_license_data = None
            # if "licenses" in d and len(d["licenses"]) > 0:
            #     license_data = d["licenses"][0]
            #     multi_license_data = d["licenses"]
            #     for l in d["licenses"]:
            #         id = name = text = url = ""
            #         if "id" in l["license"]:
            #             id = l["license"]["id"]
            #         if "name" in l["license"]:
            #             name = l["license"]["name"]
            #         if "text" in l["license"]:
            #             name = l["license"]["text"]["content"]
            #         if "url" in l["license"]:
            #             url = l["license"]["url"]
            # elif "evidence" in d:
            #     if "licenses" in d["evidence"]:
            #         if len(d["evidence"]["licenses"]) > 0:
            #             license_data = d["evidence"]["licenses"][0]
            # if license_data is not None:
            #     # Multiple ways of defining licenses
            #     license = None
            #     if "license" in license_data:
            #         if "id" in license_data["license"]:
            #             license = license_data["license"]["id"]
            #         elif "name" in license_data["license"]:
            #             license = license_data["license"]["name"]
            #         elif "expression" in license_data["license"]:
            #             license = license_data["license"]["expression"]
            #         if "acknowledgement" in license_data["license"]:
            #             acknowledgement = license_data["license"]["acknowledgement"]
            #     elif "expression" in license_data:
            #         license = license_data["expression"]
            #     if license is not None:
            #         # Assume License concluded is same as license declared
            #         # CycloneDX distinguishes between concluded and declared
            #         if self._cyclonedx_16():
            #             if acknowledgement is not None:
            #                 if acknowledgement == "concluded":
            #                     self.cyclonedx_package.set_licenseconcluded(license)
            #                 else:
            #                     self.cyclonedx_package.set_licensedeclared(license)
            #             else:
            #                 self.cyclonedx_package.set_licenseconcluded(license)
            #                 self.cyclonedx_package.set_licensedeclared(license)
            #         else:
            #             self.cyclonedx_package.set_licenseconcluded(license)
            #             self.cyclonedx_package.set_licensedeclared(license)
            # if multi_license_data is not None:
            #     self.cyclonedx_package.set_licenselist(multi_license_data)
            if "copyright" in d:
                self.cyclonedx_package.set_copyrighttext(d["copyright"])
            if "cpe" in d:
                if d["cpe"].lower().startswith("cpe:2.3"):
                    self.cyclonedx_package.set_cpe(d["cpe"])
                elif d["cpe"].lower().startswith("cpe:/"):
                    self.cyclonedx_package.set_cpe(d["cpe"], cpetype="cpe22Type")
            if "purl" in d:
                self.cyclonedx_package.set_purl(d["purl"])
            if "group" in d:
                self.cyclonedx_package.set_value("group", d["group"])
            if "evidence" in d:
                evidence = d["evidence"]
                if evidence.get("occurrences") is not None:
                    for occurrence in evidence["occurrences"]:
                        self.cyclonedx_package.set_evidence(occurrence["location"])
            if "properties" in d:
                # Potentially multiple entries
                for property in d["properties"]:
                    self.cyclonedx_package.set_property(
                        property["name"], property["value"]
                    )
            if "externalReferences" in d:
                # Potentially multiple entries
                for reference in d["externalReferences"]:
                    ref_type = reference["type"]
                    ref_url = reference["url"]
                    # Try to map type to package element
                    if ref_type == "website":
                        self.cyclonedx_package.set_homepage(ref_url)
                    elif ref_type == "distribution":
                        self.cyclonedx_package.set_downloadlocation(ref_url)
                    else:
                        self.cyclonedx_package.set_externalreference("OTHER", ref_type, ref_url)
            if "modelCard" in d:
                self._cyclonedx_mlmodel(d)
                self.cyclonedx_package.set_value(
                    "modelCard", self.model_card.get_modelcard()
                )
            # Save package metadata
            self.packages[(package, version)] = self.cyclonedx_package.get_package()
            self.id[bom_ref] = package
            # Handle component assemblies
            if "components" in d:
                for component in d["components"]:
                    self._cyclondex_component(component)

    def parse_cyclonedx_json(self, sbom_file):
        """parses CycloneDX JSON BOM file extracting package name, version and license"""
        data = json.load(open(sbom_file, "r", encoding="utf-8"))
        files = {}
        relationships = []
        # First relationship is assumed to be the root element
        relationship_type = " DESCRIBES "
        vulnerabilities = []
        services = []
        cyclonedx_relationship = SBOMRelationship()
        cyclonedx_document = SBOMDocument()
        # Check valid CycloneDX JSON file (and not SPDX)
        cyclonedx_json_file = data.get("bomFormat", False)
        if cyclonedx_json_file:
            self.cyclonedx_version = data["specVersion"]
            cyclonedx_document.set_version(self.cyclonedx_version)
            cyclonedx_document.set_type("cyclonedx")
            cyclonedx_document.set_value(
                "uuid", data.get("serialNumber", "urn:uuid:" + str(uuid.uuid4()))
            )
            if "version" in data:
                cyclonedx_document.set_value("bom_version", data["version"])
            else:
                cyclonedx_document.set_value("bom_version", 1)
            if "metadata" in data:
                if "timestamp" in data["metadata"]:
                    cyclonedx_document.set_created(data["metadata"]["timestamp"])
                if "lifecycles" in data["metadata"]:
                    for l in data["metadata"]["lifecycles"]:
                        cyclonedx_document.set_value("lifecycle", l["phase"])
                if "tools" in data["metadata"]:
                    if self._cyclonedx_15():
                        if "components" in data["metadata"]["tools"]:
                            for component in data["metadata"]["tools"]["components"]:
                                name = component["name"]
                                if "version" in component:
                                    name = f'{name}#{component["version"]}'
                                cyclonedx_document.set_creator("tool", name)
                        else:
                            # This is the legacy interface which is deprecated.
                            if self.debug:
                                print("Legacy tool(s) specification still being used.")
                            if "components" in data["metadata"]["tools"][0]:
                                name = ""
                                if "name" in data["metadata"]["tools"][0]["components"][0]:
                                    name = data["metadata"]["tools"][0]["components"][0]["name"]
                                if (
                                    "version"
                                    in data["metadata"]["tools"][0]["components"][0]
                                ):
                                    name = f'{name}#{data["metadata"]["tools"][0]["components"][0]["version"]}'
                                cyclonedx_document.set_creator("tool", name)
                    else:
                        name = data["metadata"]["tools"][0]["name"]
                        if "version" in data["metadata"]["tools"]:
                            name = f'{name}#{data["metadata"]["tools"][0]["name"]}'
                        cyclonedx_document.set_creator("tool", name)
                if "authors" in data["metadata"]:
                    for a in data["metadata"]["authors"]:
                        name = f'{a.get("name","")}#{a.get("email","")}'
                        if name != "#":
                            cyclonedx_document.set_creator("person", name)
                if "component" in data["metadata"]:
                    component_name = data["metadata"]["component"]["name"]
                    cyclonedx_document.set_name(component_name)
                    component_type = data["metadata"]["component"]["type"]
                    cyclonedx_document.set_metadata_type(component_type)
                    if "bom-ref" in data["metadata"]["component"]:
                        bom_ref = data["metadata"]["component"]["bom-ref"]
                        cyclonedx_document.set_value("bom-ref", bom_ref)
                    else:
                        bom_ref = "CylconeDX-Component-0000"
                    self.id[bom_ref] = component_name
                    if "version" in data["metadata"]["component"]:
                        component_version = data["metadata"]["component"]["version"]
                        cyclonedx_document.set_value(
                            "metadata_version", component_version
                        )
                    if "supplier" in data["metadata"]["component"]:
                        supplier = data["metadata"]["component"]["supplier"]
                        cyclonedx_document.set_value(
                            "metadata_supplier", supplier['name']
                        )
                if "properties" in data["metadata"]:
                    cyclonedx_document.set_value(
                        "property", data["metadata"]["properties"]
                    )
            if "components" in data:
                for d in data["components"]:
                    self._cyclondex_component(d)
            if "dependencies" in data:
                for d in data["dependencies"]:
                    source_id = d["ref"]
                    # Get source name
                    source = None
                    if source_id in self.id:
                        source = self.id[source_id]
                    elif self.debug:
                        print(f"[ERROR] Unable to find {source_id}")
                    if source is not None and d.get("dependsOn") is not None:
                        for target_id in d["dependsOn"]:
                            if target_id in self.id:
                                target = self.id[target_id]
                                cyclonedx_relationship.initialise()
                                cyclonedx_relationship.set_relationship(
                                    source, relationship_type, target
                                )
                                cyclonedx_relationship.set_relationship_id(
                                    source_id, target_id
                                )
                                relationships.append(
                                    cyclonedx_relationship.get_relationship()
                                )
                            elif self.debug:
                                print(f"[ERROR] Unable to find {target_id}")
                    relationship_type = " DEPENDS_ON "
            if "vulnerabilities" in data:
                vuln_info = Vulnerability(validation="cyclonedx")
                for vuln in data["vulnerabilities"]:
                    vuln_info.initialise()
                    if "bom-ref" in vuln:
                        vuln_info.set_value("bom-ref", vuln["bom-ref"])
                        if "@" in vuln["bom-ref"]:
                            component_info = vuln['bom-ref'].split('@')
                            vuln_info.set_value("product", component_info[0])
                            vuln_info.set_value("release", component_info[1])
                    vuln_info.set_id(vuln["id"])
                    if "source" in vuln:
                        vuln_info.set_value("source-name", vuln["source"]["name"])
                        vuln_info.set_value("source-url", vuln["source"]["url"])
                    if "description" in vuln:
                        vuln_info.set_description(vuln["description"])
                    if "published" in vuln:
                        vuln_info.set_value("created", vuln["published"])
                    if "updated" in vuln:
                        vuln_info.set_value("updated", vuln["updated"])
                    if "analysis" in vuln:
                        if "state" in vuln["analysis"]:
                            vuln_info.set_value("status", vuln["analysis"]["state"])
                        if "detail" in vuln["analysis"]:
                            vuln_info.set_comment(vuln["analysis"]["detail"])
                        if "response" in vuln["analysis"]:
                            for r in vuln["analysis"]["response"]:
                                vuln_info.set_remediation(r)
                        if "justification" in vuln["analysis"]:
                            vuln_info.set_value(
                                "justification", vuln["analysis"]["justification"]
                            )
                    if "affects" in vuln:
                        if "ref" in vuln["affects"][0]:
                            vuln_info.set_value("bom_link", vuln["affects"][0]["ref"])
                        if "versions" in vuln["affects"][0]:
                            if "version" in vuln["affects"][0]["versions"]:
                                vuln_info.set_release(vuln["affects"][0]["versions"]["version"])
                    vulnerabilities.append(vuln_info.get_vulnerability())
                if self.debug:
                    print(vulnerabilities)
            if "services" in data:
                service_info = SBOMService()
                service_id=1
                for service in data["services"]:
                    service_info.initialise()
                    service_info.set_id(service.get("bom-ref",f"CycloneDX-Service-{service_id}"))
                    service_info.set_name(service["name"])
                    if "version" in service:
                        service_info.set_version(service["version"])
                    if "description" in service:
                        service_info.set_description(service["description"])
                    if "provider" in service:
                        name = service["provider"].get("name", "")
                        if "url" in service["provider"]:
                            for u in service["provider"]["url"]:
                                url = u
                        contact = email = phone = ""
                        if "contact" in service["provider"]:
                            contact = service["provider"]["contact"].get("name", "")
                            email = service["provider"]["contact"].get("email", "")
                            phone = service["provider"]["contact"].get("phone", "")
                        service_info.set_provider(
                            name=name,
                            url=url,
                            contact=contact,
                            email=email,
                            phone=phone,
                        )
                    if "endpoints" in service:
                        for endpoint in service["endpoints"]:
                            service_info.set_endpoint(endpoint)
                    if "authenticated" in service:
                        service_info.set_value(
                            "authenticated", service["authenticated"]
                        )
                    if "x-trust-boundary" in service:
                        service_info.set_value(
                            "x-trust-boundary", service["x-trust-boundary"]
                        )
                    if "trustZone" in service:
                        service_info.set_value("trustZone", service["trustZone"])
                    if "data" in service:
                        for data_element in service["data"]:
                            flow = data_element.get("flow")
                            classification = data_element.get("classification")
                            name = data_element.get("name", "")
                            description = data_element.get("description", "")
                            service_info.set_data(
                                flow, classification, name=name, description=description
                            )
                    if "licenses" in service:
                        for license in service["licenses"]:
                            service_info.set_license(license["license"])
                    if "properties" in service:
                        for property in service["properties"]:
                            service_info.set_property(
                                property["name"], property["value"]
                            )
                    if "externalreference" in service:
                        for reference in service["externalreference"]:
                            url = reference.get("url")
                            external_type = reference.get("type")
                            comment = reference.get("comment", "")
                            service_info.set_externalreference(
                                url, external_type, comment=comment
                            )
                    services.append(service_info.get_service())
                    service_id = service_id + 1
                if self.debug:
                    print(services)
        return (
            cyclonedx_document,
            files,
            self.packages,
            relationships,
            vulnerabilities,
            services,
            self.licences
        )

    def _parse_component(self, component_element):
        """Parses a CycloneDX component element and returns a dictionary of its contents."""
        component = {}
        # Get the attributes of the component element.
        attributes = component_element.attrib
        # Add the attributes to the component dictionary.
        for attribute in attributes:
            component[attribute] = attributes[attribute]
        # Get the child elements of the component element.
        children = component_element.getchildren()
        # Iterate over the child elements of the component element.
        for child in children:
            # Get the tag name and text of the child element.
            tag = child.tag
            component[tag] = self._parse_dependencies(child)
        return component

    def parse_document_xml(self):
        cyclonedx_document = SBOMDocument()
        # Extract CycloneDX version from schema
        cyclonedx_version = self.schema.replace("}", "").split("/")[-1]
        cyclonedx_document.set_version(cyclonedx_version)
        cyclonedx_document.set_type("cyclonedx")
        component_name = None
        bom_ref = None

        for metadata in self.root.findall(self.schema + "metadata"):
            timestamp = self._xml_component(metadata, "timestamp")
            if timestamp != "":
                cyclonedx_document.set_created(timestamp)
            for tools in metadata.findall(self.schema + "tools"):
                for tool in tools.findall(self.schema + "tool"):
                    name = self._xml_component(tool, "name")
                    version = self._xml_component(tool, "version")
                    cyclonedx_document.set_creator("tool", f"{name}#{version}")
            for authors in metadata.findall(self.schema + "authors"):
                for author in authors.findall(self.schema + "author"):
                    name = self._xml_component(author, "name")
                    email = self._xml_component(author, "email")
                    if email != "":
                        name = f"{name}#{email}"
                    cyclonedx_document.set_creator("person", name)
            for component in metadata.findall(self.schema + "component"):
                component_name = self._xml_component(component, "name")
                attrib = component.attrib
                bom_ref = attrib.get("bom-ref")
                cyclonedx_document.set_name(component_name)
            if component_name is not None and bom_ref is not None:
                cyclonedx_document.set_value("bom-ref", bom_ref)
                self.id[bom_ref] = component_name
        return cyclonedx_document

    def _xml_component(self, item, element):
        data = item.find(self.schema + element)
        if data is not None:
            return data.text.strip()
        return ""

    def _parse_component_xml(self, component):
        self.cyclonedx_package.initialise()
        self.component_id = self.component_id + 1
        # Record type of component
        self.cyclonedx_package.set_type(component.attrib["type"])
        package = self._xml_component(component, "name")
        version = self._xml_component(component, "version")
        self.cyclonedx_package.set_name(package)
        self.cyclonedx_package.set_version(version)
        attrib = component.attrib
        bom_ref = attrib.get("bom-ref")
        if bom_ref is None:
            bom_ref = f"CycloneDX-Component-{self.component_id}"
        self.cyclonedx_package.set_value("bom-ref", bom_ref)
        for supplier in component.findall(self.schema + "supplier"):
            supplier_name = self._xml_component(supplier, "name")
            for element in supplier.findall(self.schema + "contact"):
                email = self._xml_component(element, "email")
                if email != "":
                    # contact_name = self._xml_component(element, "name")
                    supplier_name = f"{supplier_name} ({email})"
                    break
            self.cyclonedx_package.set_supplier("Organisation", supplier_name)
        author = self._xml_component(component, "author")
        if author != "":
            # Assume that this refers to an individual
            self.cyclonedx_package.set_originator("Person", author)
        description = self._xml_component(component, "description")
        if description != "":
            self.cyclonedx_package.set_copyrighttext(description)
        for hashes in component.findall(self.schema + "hashes"):
            for hash in hashes.findall(self.schema + "hash"):
                self.cyclonedx_package.set_checksum(str(hash.attrib["alg"]), hash.text)
        for licenses in component.findall(self.schema + "licenses"):
            for license in licenses.findall(self.schema + "license"):
                # Multiple ways of defining license data
                license_id = self._xml_component(licenses, "expression")
                if license_id == "":
                    license_id = self._xml_component(license, "id")
                    if license_id == "":
                        license_id = self._xml_component(license, "name")
                if license_id != "":
                    # Assume License concluded is same as license declared
                    self.cyclonedx_package.set_licenseconcluded(license_id)
                    self.cyclonedx_package.set_licensedeclared(license_id)
        copyright = self._xml_component(component, "copyright")
        if copyright != "":
            self.cyclonedx_package.set_copyrighttext(copyright)
        cpe = self._xml_component(component, "cpe")
        if cpe != "":
            if cpe.lower().startswith("cpe:2.3"):
                self.cyclonedx_package.set_cpe(cpe)
            elif cpe.lower().startswith("cpe:/"):
                self.cyclonedx_package.set_cpe(cpe, cpetype="cpe22Type")
        purl = self._xml_component(component, "purl")
        if purl != "":
            self.cyclonedx_package.set_purl(purl)
        # Potentially multiple entries
        for properties in component.findall(self.schema + "properties"):
            for property in properties.findall(self.schema + "property"):
                params = property.attrib
                # Handle different ways of specifying property
                if params.get("value") is not None:
                    # Explicit value specified as attribute
                    self.cyclonedx_package.set_property(params["name"], params["value"])
                else:
                    # Implicit value
                    self.cyclonedx_package.set_property(params["name"], property.text)
        for references in component.findall(self.schema + "externalReferences"):
            for reference in references.findall(self.schema + "reference"):
                params = reference.attrib
                ref_type = params.get("type")
                ref_url = self._xml_component(reference, "url")
                # Try to map type to package element
                if ref_type == "website":
                    self.cyclonedx_package.set_homepage(ref_url)
                elif ref_type == "distribution":
                    self.cyclonedx_package.set_downloadlocation(ref_url)

        # Save package metadata
        self.packages[(package, version)] = self.cyclonedx_package.get_package()
        self.id[bom_ref] = package
        # Handle component assembly
        for components in component.findall(self.schema + "components"):
            for component_assembly in components.findall(self.schema + "component"):
                self._parse_component_xml(component_assembly)

    def parse_components_xml(self):
        for components in self.root.findall(self.schema + "components"):
            for component in components.findall(self.schema + "component"):
                self._parse_component_xml(component)

    def parse_dependencies_xml(self):
        relationships = []
        cyclonedx_relationship = SBOMRelationship()
        # First relationship is assumed to be the root element
        relationship_type = " DESCRIBES "
        for dependency in self.root.findall(self.schema + "dependencies"):
            for depends in dependency.findall(self.schema + "dependency"):
                source = depends.attrib["ref"]
                source_id = self.id[source]
                for depend in depends.findall(self.schema + "dependency"):
                    # Get ids
                    target_id = self.id[depend.attrib["ref"]]
                    cyclonedx_relationship.initialise()
                    cyclonedx_relationship.set_relationship(
                        source_id, relationship_type, target_id
                    )
                    cyclonedx_relationship.set_relationship_id(
                        source, depend.attrib["ref"]
                    )
                    relationships.append(cyclonedx_relationship.get_relationship())
                    relationship_type = " DEPENDS_ON "
        return relationships

    def parse_vulnerabilities_xml(self):
        # TODO
        vulnerabilities = []
        return vulnerabilities

    def parse_services_xml(self):
        # TODO
        services = []
        return services

    def parse_cyclonedx_xml(self, sbom_file):
        self.tree = ET.parse(sbom_file)
        self.root = self.tree.getroot()
        # Extract schema
        self.schema = self.root.tag[: self.root.tag.find("}") + 1]
        document = self.parse_document_xml()
        self.parse_components_xml()
        dependencies = self.parse_dependencies_xml()
        vulnerabilities = self.parse_vulnerabilities_xml()
        services = self.parse_services_xml()
        return document, {}, self.packages, dependencies, vulnerabilities, services, self.licences
