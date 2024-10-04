# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to create a CycloneDX SBOM in JSON format

from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.service import SBOMService
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
#### This overwrites the package (same name and version)
sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()

# ML Component
my_package.initialise()
my_package.set_name("resnet-50")
my_package.set_type("machine-learning-model")
my_package.set_version("1.5")
my_package.set_supplier("organisation", "microsoft")
my_package.set_licensedeclared("Apache-2.0")
my_package.set_description(
    "ResNet (Residual Network) is a convolutional neural network that democratized the concepts of residual learning and skip connections. This enables to train much deeper models."
)
# Define Services

sbom_services = {}
my_service = SBOMService()
my_service.set_name("Microsoft 365")
my_service.set_version("2022.04")
my_service.set_provider(
    name="Microsoft Inc.", contact="Fred Flintstone", email="fred@micrsoft.com"
)
my_service.set_description("Business productivity suite")
my_service.set_endpoint("www.microsoft.com")
my_service.set_endpoint("www.microsoft.com/owa")
my_service.set_value("authenticated", True)
my_service.set_data("Bi-directional", "None", description="document")
my_service.set_data("outbound", "PII", name="User information")
my_service.set_license("Apache-2.0")
my_service.set_license("MIT")
my_service.set_property("Data_Location", "EU")
my_service.set_externalreference(
    "https://www.microsoft.com", "Website", "Company website"
)
# my_service.setendpoint(name=xx, type="", data="")
sbom_services[
    (my_service.get_name(), my_service.get_value("version"))
] = my_service.get_service()

# Generate SBOM
my_sbom = SBOM()
my_sbom.set_type(sbom_type="cyclonedx")
my_sbom.add_packages(sbom_packages)
my_sbom.add_services(sbom_services)

# print(my_sbom.get_sbom())
#
my_generator = SBOMGenerator(False, sbom_type="cyclonedx", format="json")
# Will be displayed on console
# print(my_sbom.get_sbom())

my_generator.generate("ServiceApp", my_sbom.get_sbom())

# Send to file
