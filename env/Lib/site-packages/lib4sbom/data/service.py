# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import re

from lib4sbom.license import LicenseScanner


class SBOMService:
    def __init__(self):
        self.service = {}
        self.license = LicenseScanner()

    def _text(self, text_item):
        return text_item.replace("<text>", "").replace("</text>", "")

    def _url_valid(self, url):
        url_pattern = (
            "(http:\\/\\/www\\.|https:\\/\\/www\\.|http:\\/\\/|https:\\/\\/|ssh:\\/\\/|git:\\/\\/|svn:\\/\\/|sftp:"
            "\\/\\/|ftp:\\/\\/)?[a-z0-9]+([\\-\\.]{1}[a-z0-9]+){0,100}\\.[a-z]{2,5}(:[0-9]{1,5})?(\\/.*)?"
        )
        # Simple check to catch multiple URLs
        if " " in url:
            return False
        check_url = re.match(url_pattern, url)
        if check_url is None:
            # No match
            return False
        # Check URL is fully matched
        return check_url.group(0) == url

    def initialise(self):
        self.service = {}

    def set_name(self, name):
        self.service["name"] = name

    def set_id(self, id):
        self.service["id"] = id

    def _flow_type(self, type):
        # Handle all types as upper case.
        flow_type = type.lower().replace("_", "-").strip()
        if flow_type in [
            "inbound",
            "outbound",
            "bi-directional",
            "unknown",
        ]:
            return flow_type
        else:
            return "unknown"

    def set_version(self, version):
        self.service["version"] = self._semantic_version(version)
        my_id = self.service.get("id")
        my_name = self.get_name()
        if my_id is None and my_name is not None:
            self.set_id(self.get_name() + "_" + str(self.service["version"]))

    def set_provider(self, name="", url="", contact="", email="", phone=""):
        provider = {}
        if len(name) > 0:
            provider["name"] = name
        if len(url) > 0 and self._url_valid(url):
            provider["url"] = url
        if len(contact) > 0:
            provider["contact"] = contact
        if len(email) > 0:
            provider["email"] = email
        if len(phone) > 0:
            provider["phone"] = phone
        # Make sure at least one parameter has been provided
        if len(provider) > 0:
            self.service["provider"] = provider

    def set_endpoint(self, endpoint_url):
        # Allow multiple entries
        if self._url_valid(endpoint_url):
            if "endpoints" in self.service:
                self.service["endpoints"].append(endpoint_url)
            else:
                self.service["endpoints"] = [endpoint_url]

    def set_data(self, flow, classification, name="", description=""):
        # Allow multiple entries
        data_entry = {"flow": self._flow_type(flow), "classification": classification}
        if len(name) > 0:
            data_entry["name"] = name
        if len(description) > 0:
            data_entry["description"] = description
        if "data" in self.service:
            self.service["data"].append(data_entry)
        else:
            self.service["data"] = [data_entry]

    def set_property(self, name, value):
        # Allow multiple entries
        property_entry = [name.strip(), value]
        if "property" in self.service:
            self.service["property"].append(property_entry)
        else:
            self.service["property"] = [property_entry]

    def set_license(self, license_info):
        # Validate license
        license_id = self.license.find_license(license_info)
        # Only include if valid license
        if license_id != "UNKNOWN":
            if "licenseinfo" in self.service:
                self.service["licenseinfo"].append(license_info)
            else:
                self.service["licenseinfo"] = [license_info]

    def _validate_type(self, type):
        external_ref_types = [
            "vcs",  # Version Control System
            "issue-tracker",  # Issue or defect tracking system, or an Application Lifecycle Management (ALM) system
            "website",  # Website
            "advisories",  # Security advisories
            "bom",  # Bill of Materials (SBOM, OBOM, HBOM, SaaSBOM, etc)
            "mailing-list",  # Mailing list or discussion group
            "social",  # Social media account
            "chat",  # Real-time chat platform
            "documentation",  # Documentation, guides, or how-to instructions
            "support",  # Community or commercial support
            "distribution",  # Direct or repository download location
            "distribution-intake",  # The location where a component was published to. This is often the same as "distribution" but may also include specialized publishing processes that act as an intermediary
            "license",  # The URL to the license file. If a license URL has been defined in the license node, it should also be defined as an external reference for completeness
            "build-meta",  # Build-system specific meta file (i.e. pom.xml, package.json, .nuspec, etc)
            "build-system",  # URL to an automated build system
            "release-notes",  # URL to release notes
            "security-contact",  # Specifies a way to contact the maintainer, supplier, or provider in the event of a security incident. Common URIs include links to a disclosure procedure, a mailto (RFC-2368) that specifies an email address, a tel (RFC-3966) that specifies a phone number, or dns (RFC-4501) that specifies the records containing DNS Security TXT
            "model-card",  # A model card describes the intended uses of a machine learning model, potential limitations, biases, ethical considerations, training parameters, datasets used to train the model, performance metrics, and other relevant data useful for ML transparency
            "log",  # A record of events that occurred in a computer system or application, such as problems, errors, or information on current operations
            "configuration",  # Parameters or settings that may be used by other components or services
            "evidence",  # Information used to substantiate a claim
            "formulation",  # Describes how a component or service was manufactured or deployed
            "attestation",  # Human or machine-readable statements containing facts, evidence, or testimony
            "threat-model",  # An enumeration of identified weaknesses, threats, and countermeasures, dataflow diagram (DFD), attack tree, and other supporting documentation in human-readable or machine-readable format
            "adversary-model",  # The defined assumptions, goals, and capabilities of an adversary.
            "risk-assessment",  # Identifies and analyzes the potential of future events that may negatively impact individuals, assets, and/or the environment. Risk assessments may also include judgments on the tolerability of each risk.
            "vulnerability-assertion",  # A Vulnerability Disclosure Report (VDR) which asserts the known and previously unknown vulnerabilities that affect a component, service, or product including the analysis and findings describing the impact (or lack of impact) that the reported vulnerability has on a component, service, or product.
            "exploitability-statement",  # A Vulnerability Exploitability eXchange (VEX) which asserts the known vulnerabilities that do not affect a product, product family, or organization, and optionally the ones that do. The VEX should include the analysis and findings describing the impact (or lack of impact) that the reported vulnerability has on the product, product family, or organization.
            "pentest-report",  # Results from an authorized simulated cyberattack on a component or service, otherwise known as a penetration test
            "static-analysis-report",  # SARIF or proprietary machine or human-readable report for which static analysis has identified code quality, security, and other potential issues with the source code
            "dynamic-analysis-report",  # Dynamic analysis report that has identified issues such as vulnerabilities and misconfigurations
            "runtime-analysis-report",  # Report generated by analyzing the call stack of a running application
            "component-analysis-report",  # Report generated by Software Composition Analysis (SCA), container analysis, or other forms of component analysis
            "maturity-report",  # Report containing a formal assessment of an organization, business unit, or team against a maturity model
            "certification-report",  # Industry, regulatory, or other certification from an accredited (if applicable) certification body
            "quality-metrics",  # Report or system in which quality metrics can be obtained
            "codified-infrastructure",  # Code or configuration that defines and provisions virtualized infrastructure, commonly referred to as Infrastructure as Code (IaC)
            "poam",  # Plans of Action and Milestones (POAM) compliment an "attestation" external reference. POAM is defined by NIST as a "document that identifies tasks needing to be accomplished. It details resources required to accomplish the elements of the plan, any milestones in meeting the tasks and scheduled completion dates for the milestones".
            "other",  # Use this if no other types accurately describe the purpose of the external reference
        ]
        if type.lower() in external_ref_types:
            return type.lower()
        return "other"

    def set_externalreference(self, url, type, comment=""):
        # Allow multiple entries
        if self._url_valid(url):
            reference_entry = [url, self._validate_type(type), comment]
            if "externalreference" in self.service:
                self.service["externalreference"].append(reference_entry)
            else:
                self.service["externalreference"] = [reference_entry]

    def set_description(self, description):
        self.service["description"] = self._text(description)

    def set_value(self, key, value):
        self.service[key] = value

    def get_service(self):
        return self.service

    def get_value(self, attribute):
        return self.service.get(attribute, None)

    def debug_service(self):
        print("OUTPUT:", self.service)

    def show_service(self):
        for key in self.service:
            print(f"{key}    : {self.service[key]}")

    def copy_service(self, service_info):
        for key in service_info:
            self.set_value(key, service_info[key])

    def get_name(self):
        return self.get_value("name")

    def _semantic_version(self, version):
        return version.split("-")[0] if "-" in version else version
