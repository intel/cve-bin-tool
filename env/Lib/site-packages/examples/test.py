from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.file import SBOMFile
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.data.vulnerability import Vulnerability
from lib4sbom.generator import SBOMGenerator
from lib4sbom.sbom import SBOM, SBOMData


def generate_sbom():
    sbom = SBOM()
    sbom.set_type(sbom_type="cyclonedx")
    sbom.set_version("1.4")
    sbom.set_uuid("urn:uuid:My_uuid_1234")
    sbom.set_bom_version("2")

    sbom_doc = SBOMDocument()
    sbom_doc.set_metadata_type("firmware")
    sbom_doc.set_metadata_supplier("Acme Inc.")
    sbom_doc.set_metadata_version("1.0a")
    sbom.add_document(sbom_doc.get_document())

    sbom_packages = {}

    # To Level Package
    parent_app = "iOSApp"
    iosapp_pkg = SBOMPackage()
    iosapp_pkg.set_name(parent_app)
    iosapp_pkg.set_version("1")
    iosapp_pkg.set_supplier("Author", "RH")
    iosapp_pkg.set_type("Application")
    iosapp_pkg.set_licensedeclared("Apache-2.0")
    parent_id = "iOSApp_Application"
    iosapp_pkg.set_id(parent_id)
    sbom_packages[
        (iosapp_pkg.get_name(), iosapp_pkg.get_value("version"))
    ] = iosapp_pkg.get_package()

    # swift-log
    swiftlog_pkg = SBOMPackage()
    swiftlog_pkg.set_name("swift-log")
    swiftlog_pkg.set_version("1.5.2")
    swiftlog_pkg.set_supplier("Author", "Apple Inc.")
    swiftlog_pkg.set_homepage("https://github.com/apple/swift-log")
    # swiftlog_pkg.set_licensedeclared("Apache-2.0")
    swiftlog_pkg.set_licenseconcluded("Apache-2.0")
    swiftlog_pkg.set_id(
        swiftlog_pkg.get_name().lower()
        + ".apple.com@"
        + swiftlog_pkg.get_value("version")
    )
    sbom_packages[
        (swiftlog_pkg.get_name(), swiftlog_pkg.get_value("version"))
    ] = swiftlog_pkg.get_package()

    # SwiftTrace
    swifttrace_pkg = SBOMPackage()
    swifttrace_pkg.set_name("SwiftTrace")
    swifttrace_pkg.set_version("8.4.6")
    swifttrace_pkg.set_supplier("Author", "John Holdsworth")
    swifttrace_pkg.set_homepage("https://github.com/johnno1962/SwiftTrace")
    swifttrace_pkg.set_licensedeclared(
        "Copyright (c) 2015 John Holdsworth\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\n"
        'of this software and associated documentation files (the "Software"), to deal\n'
        "in the Software without restriction, including without limitation the rights\n"
        "to use, copy, modify, merge, publish, distribute, sublicense, and\/or sell\n"
        "copies of the Software, and to permit persons to whom the Software is\n"
        "furnished to do so, subject to the following conditions:\n\n"
        "The above copyright notice and this permission notice shall be included in\n"
        "all copies or substantial portions of the Software.\n\n"
        'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n'
        "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
        "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
        "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
        "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"
        "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN\n"
        "THE SOFTWARE.\n\nThis software contains code written by Oliver Letterer obtained from the\n"
        "following github project which is licensed under the terms of that project:\n\n"
        "https:\/\/github.com\/OliverLetterer\/imp_implementationForwardingToSelector\n\n"
        "Now uses the very handy https:\/\/github.com\/facebook\/fishhook.\n"
        "See the source and header files for licensing details.\n",
        name="SwiftTrace License",
    )
    swifttrace_pkg.set_id(
        swifttrace_pkg.get_name().lower() + "@" + swifttrace_pkg.get_value("version")
    )
    sbom_packages[
        (swifttrace_pkg.get_name(), swifttrace_pkg.get_value("version"))
    ] = swifttrace_pkg.get_package()

    sbom.add_packages(sbom_packages)
    relationships = []
    sbom_relationship = SBOMRelationship()

    for package in sbom.get_packages():
        # Add relationship. All components are direct dependencies.
        sbom_relationship.initialise()
        if package["name"] == parent_app:
            # Parent component
            sbom_relationship.set_relationship(parent_id, "DESCRIBES", parent_app)
            sbom_relationship.set_relationship_id(None, parent_id)
        else:
            sbom_relationship.set_relationship(
                parent_app, "DEPENDS_ON", package["name"]
            )
            sbom_relationship.set_relationship_id(parent_id, package["id"])
        relationships.append(sbom_relationship.get_relationship())
    sbom.add_relationships(relationships)

    #### VULNERABILITIES - Normally separate from SBOM
    vulnerabilities = []

    vulnerability = Vulnerability(validation="cyclonedx")
    vulnerability.set_id("CVE-2020-2345")
    vulnerability.set_name(swifttrace_pkg.get_name())
    vulnerability.set_release(swifttrace_pkg.get_value("version"))
    vulnerability.set_value("bom-ref", swifttrace_pkg.get_value("id"))
    vulnerability.set_status("not_affected")
    vulnerability.set_comment("Vulnerable function is not used.")
    vulnerabilities.append(vulnerability.get_vulnerability())

    vulnerability = Vulnerability(validation="cyclonedx")
    vulnerability.set_id("CVE-2023-1235")
    vulnerability.set_name(swifttrace_pkg.get_name())
    vulnerability.set_release(swifttrace_pkg.get_value("version"))
    vulnerability.set_value("bom-ref", swifttrace_pkg.get_value("id"))
    vulnerability.set_status("in_triage")
    vulnerabilities.append(vulnerability.get_vulnerability())

    sbom.add_vulnerabilities(vulnerabilities)

    sbg = SBOMGenerator(format="json", sbom_type="cyclonedx")

    sbg.generate(parent_id, sbom.get_sbom(), "test.json")
    # sbg.generate("iOSApp", sbom.get_sbom(), "mybomy-bom.json")


generate_sbom()
