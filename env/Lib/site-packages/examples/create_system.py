# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to create a CycloneDX SBOM in JSON format

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.sbom import SBOM

# Create packages
application = "application_name"
application_id = "CDXRef-DOCUMENT"

relationships = []
sbom_relationship = SBOMRelationship()
sbom_relationship.initialise()
sbom_relationship.set_relationship(application_id, "DESCRIBES", application)
sbom_relationship.set_relationship_id(None, application_id)
relationships.append(sbom_relationship.get_relationship())

sbom_packages = {}
my_package = SBOMPackage()

my_package.initialise()
my_package.set_name("almalinux")
my_package.set_type("operating-system")
my_package.set_version("9.0")
my_package.set_supplier("organisation", "alma")
my_package.set_licensedeclared("Apache-2.0")
my_package.set_externalreference("OTHER", "bom-link", "alma.json")
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()
sbom_relationship.initialise()
sbom_relationship.set_relationship(
    application, "DEPENDS_ON", my_package.get_value("name")
)
sbom_relationship.set_relationship_id(application_id, my_package.get_value("id"))
relationships.append(sbom_relationship.get_relationship())

my_package.initialise()
my_package.set_name("sbomlens")
my_package.set_type("container")
my_package.set_version("0.1.0")
my_package.set_supplier("organisation", "aph10")
my_package.set_externalreference("OTHER", "bom-link", "sbomlens.json")
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()
sbom_relationship.initialise()
sbom_relationship.set_relationship(
    application, "DEPENDS_ON", my_package.get_value("name")
)
sbom_relationship.set_relationship_id(application_id, my_package.get_value("id"))
relationships.append(sbom_relationship.get_relationship())

# Generate SBOM
my_sbom = SBOM()
my_sbom.set_type(sbom_type="cyclonedx")
my_sbom.set_version("1.6")
my_doc = SBOMDocument()
my_doc.set_value("lifecycle", "build")
my_doc.set_metadata_type("application")
my_doc.set_metadata_supplier("Acme Inc.")
my_doc.set_metadata_version("0.1.0")
my_sbom.add_document(my_doc.get_document())
my_sbom.add_packages(sbom_packages)
my_sbom.add_relationships(relationships)
# print(my_sbom.get_sbom())
#
#
my_generator = SBOMGenerator(False, sbom_type="cyclonedx", format="json")
# Will be displayed on console
my_generator.generate(application, my_sbom.get_sbom())

# Send to file
