# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to create a CycloneDX SBOM in JSON format

from lib4sbom.data.modelcard import ModelDataset, ModelGraphicset, SBOMModelCard
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
# Define model card
my_mlmodel = SBOMModelCard()
# my_mlmodel.set_name("awesome")
my_mlmodel.set_model_type("supervised")
my_mlmodel.set_task("classification")
my_mlmodel.set_architecture("Convolutional neural network")
my_mlmodel.set_model("ResNet-50")
my_mlmodel.set_inputs("image")
my_mlmodel.set_outputs("image class")
my_mlmodel.set_user("Researcher")
# Some Quantitative Analysis
my_mlmodel.set_performance("CPU", "10%", "", "8", "12")
my_graphicset = ModelGraphicset()
my_graphicset.set_description("Test data")
my_graphicset.add_image("cat", "cat.jpg")
my_graphicset.add_image("dog", "dog.jpg")
my_mlmodel.set_graphics(my_graphicset.get_graphicset())
# Model properties
my_mlmodel.set_property("num_channels", "3")
# Considerations
my_mlmodel.set_limitation("To be used in the EU.")
my_mlmodel.set_limitation("To be used in the UK.")
my_mlmodel.set_ethicalrisk(
    "User from prohibited location", "Use geolocation to validate source of request."
)

# Model data set
mlmodel_data = ModelDataset()
mlmodel_data.set_name("ImageNet")
mlmodel_data.set_dataset_type("dataset")
mlmodel_data.set_description(
    'ILSVRC 2012, commonly known as "ImageNet" is an image dataset organized according to the WordNet hierarchy. Each meaningful concept in WordNet, possibly described by multiple words or word phrases, is called a "synonym set" or "synset". There are more than 100,000 synsets in WordNet, majority of them are nouns (80,000+). ImageNet aims to provide on average 1000 images to illustrate each synset. Images of each concept are quality-controlled and human-annotated.'
)
mlmodel_data.set_classification("public")
mlmodel_data.set_sensitive_data("no personal data")
# mlmodel_data.set_contents(content="Image files", content_type="image/jpeg")
mlmodel_data.set_contents(url="https://huggingface.co/datasets/imagenet-1k")
mlmodel_data.set_governance(
    owner={"organization": "microsoft", "contact": "sales@microsoft.com"}
)
mlmodel_data.set_governance(
    owner={"organization": "microsoft", "contact": "consulting@microsoft.com"}
)
# Add dataset to model card
my_mlmodel.set_dataset(mlmodel_data.get_dataset())
# Add model card to component
my_package.set_value("modelcard", my_mlmodel.get_modelcard())

sbom_packages[
    (my_package.get_name(), my_package.get_value("version"))
] = my_package.get_package()

# Generate SBOM
my_sbom = SBOM()
my_sbom.set_type(sbom_type="cyclonedx")
my_sbom.add_packages(sbom_packages)

# print(my_sbom.get_sbom())
#
my_generator = SBOMGenerator(False, sbom_type="cyclonedx", format="json")
# Will be displayed on console
my_generator.generate("MLApp", my_sbom.get_sbom())

# Send to file
