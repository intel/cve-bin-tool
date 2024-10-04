# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to create a CycloneDX SBOM in JSON format

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.package import SBOMPackage
from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.sbom import SBOM

# Create packages
sbom_packages = {}
my_package = SBOMPackage()
my_package.set_name("glibc")
my_package.set_version("2.15")
my_package.set_supplier("organisation", "gnu")
my_package.set_licensedeclared("GPL3")
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()
my_package.initialise()
my_package.set_name("almalinux")
my_package.set_type("operating-system")
my_package.set_version("9.0")
my_package.set_supplier("organisation", "alma")
my_package.set_licensedeclared("Apache-2.0")
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()
my_package.initialise()
my_package.set_name("glibc")
my_package.set_version("2.29")
my_package.set_supplier("organisation", "gnu")
my_package.set_licensedeclared("GPL3")
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()
my_package.initialise()
my_package.set_name("tomcat")
my_package.set_version("9.0.46")
my_package.set_supplier("organisation", "apache")
my_package.set_licensedeclared("Apache-2.0")
# Not a real hash value!
my_package.set_checksum("SHA256", "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()
# Duplicated data
my_package.initialise()
my_package.set_name("glibc")
my_package.set_version("2.29")
my_package.set_property("language", "C")
my_package.set_supplier("organisation", "gnu")
my_package.set_licensedeclared("GPL3")
my_package.set_evidence("/bin/lib/glibc.o")
my_package.set_evidence("/bin/lib64/glibc.o")
#### This overwrites the package (same name and version)
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()
# Generate SBOM
my_sbom = SBOM()
my_sbom.set_type(sbom_type="cyclonedx")
my_sbom.set_version("1.6")
my_doc = SBOMDocument()
my_doc.set_value("lifecycle", "build")
my_sbom.add_document(my_doc.get_document())
my_sbom.add_packages(sbom_packages)
# print(my_sbom.get_sbom())
#
#
my_generator = SBOMGenerator(False, sbom_type="cyclonedx", format="json")
# Will be displayed on console
my_generator.generate("TestApp", my_sbom.get_sbom())

# Send to file
