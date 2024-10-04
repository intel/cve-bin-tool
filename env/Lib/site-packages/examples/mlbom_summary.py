import copy
import pprint
import sys

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.modelcard import ModelDataset, ModelGraphicset, SBOMModelCard
from lib4sbom.parser import SBOMParser

test_parser = SBOMParser()
# Load SBOM
try:
    test_parser.parse_file(sys.argv[1])

    # What type of SBOM
    document = SBOMDocument()
    document.copy_document(test_parser.get_document())

    packages = test_parser.get_packages()

    sbom_type = document.get_type()
    sbom_version = document.get_version()
    print(f"SBOM Type    {sbom_type}")
    print(f"Version      {sbom_version}")

    if sbom_type == "cyclonedx" and sbom_version == "1.5":
        # ML BOM is only for Version 1.5 (CycloneDX) and above
        if len(packages) > 0:
            for package in packages:
                print("\n==========PACKAGE============\n")
                print(f'Id: {package.get("id", None)}')
                print(f'Name: {package.get("name", None)}')
                print(f'Version: {package.get("version", None)}')
                print(f'Supplier: {package.get("supplier", "Not known")}')
                print(f'License: {package.get("licenseconcluded", "Not known")}')
                print(f'Type: {package.get("type", None)}')
                if package["type"] == "MACHINE-LEARNING-MODEL":
                    # print (package)
                    if package.get("modelCard") is not None:
                        modelCard = package["modelCard"]
                        if "id" in modelCard:
                            print(f"bom-ref2: {modelCard['id']}")
                        # Model Parameters
                        title = False
                        if "learning_type" in modelCard:
                            if not title:
                                print("Model Parameters")
                                title = True
                            print(f"\tApproach: {modelCard['learning_type']}")
                        if "task" in modelCard:
                            if not title:
                                print("Model Parameters")
                                title = True
                            print(f"\tTask: {modelCard['task']}")
                        if "architecture" in modelCard:
                            if not title:
                                print("Model Parameters")
                                title = True
                            print(
                                f"\tArchitecture Familiy: {modelCard['architecture']}"
                            )
                        if "model" in modelCard:
                            if not title:
                                print("Model Parameters")
                                title = True
                            print(f"\tModel Architecture: {modelCard['model']}")
                        if "dataset" in modelCard:
                            if not title:
                                print("Model Parameters")
                                title = True
                            print("Datasets")
                            for dataset in modelCard["dataset"]:
                                print(f"\tType: {dataset['dataset_type']}")
                                print(f"\tName: {dataset['name']}")
                                print(f"\tId: {dataset['id']}")
                                # Contents
                                if "content" in dataset:
                                    print(f"Contents: {dataset['content']}")
                                if "url" in dataset:
                                    print(f"\tContents URL: {dataset['url']}")
                                if "property" in dataset:
                                    for property in dataset["property"]:
                                        print(
                                            f"\tName: {property[0]} Value: {property[1]}"
                                        )
                                print(f"\tClassification: {dataset['classification']}")
                                if "sensitive_data" in dataset:
                                    print(
                                        f"\tSensitive Data: {dataset['sensitive_data']}"
                                    )
                                # Graphics
                                if "graphics" in dataset:
                                    print("Graphics")
                                    print(
                                        f"\tDescription: {dataset['graphics']['description']}"
                                    )
                                    for image in dataset["graphics"]["collection"]:
                                        print(f"\tImage: {image[0]} {image[1]}")
                                if "description" in dataset:
                                    print(f"\tDescription: {dataset['description']}")
                                # Governance
                                if "custodian" in dataset:
                                    print("\tCustodians")
                                    for custodian in dataset["custodian"]:
                                        print(
                                            f"\tOrganization {custodian.get('organization')}\tContact {custodian.get('contact')}"
                                        )
                                if "steward" in dataset:
                                    print("\tStewards")
                                    for steward in dataset["steward"]:
                                        print(
                                            f"\tOrganization {steward.get('organization')}\tContact {steward.get('contact')}"
                                        )
                                if "owner" in dataset:
                                    print("\tOwners")
                                    for owner in dataset["owner"]:
                                        print(
                                            f"\tOrganization {owner.get('organization')}\tContact {owner.get('contact')}"
                                        )
                        if "inputs" in modelCard:
                            if not title:
                                print("Model Parameters")
                                title = True
                            for input in modelCard["inputs"]:
                                print(f"\tInput: {input}")
                        if "outputs" in modelCard:
                            if not title:
                                print("Model Parameters")
                                title = True
                            for output in modelCard["outputs"]:
                                print(f"\tOutput: {output}")
                        # Quantitative Analysis
                        title = False
                        if "performance" in modelCard:
                            if not title:
                                print("Quantitative Analysis")
                                title = True
                            print("Performance Metrics")
                            for performance in modelCard["performance"]:
                                print(
                                    f"\tType: {performance[0]} Value {performance[1]} Slice: {performance[2]} Lower Bound: {performance[3]} Upper Bound : {performance[4]}"
                                )
                        if "graphics" in modelCard:
                            if not title:
                                print("Quantitative Analysis")
                                title = True
                            print("Graphics")
                            print(
                                f"\tDescription: {modelCard['graphics']['description']}"
                            )
                            for image in modelCard["graphics"]["collection"]:
                                print(f"\tImage: {image[0]} {image[1]}")
                        # Considerations
                        title = False
                        if "user" in modelCard:
                            if not title:
                                print("Considerations\n")
                                title = True
                            print("Users")
                            for user in modelCard["user"]:
                                print(f"\t{user}")
                        if "usecase" in modelCard:
                            if not title:
                                print("Considerations\n")
                                title = True
                            print("Use Cases")
                            for usecase in modelCard["usecase"]:
                                print(f"\t{usecase}")
                        if "limitation" in modelCard:
                            if not title:
                                print("Considerations\n")
                                title = True
                            print("Technical Limitations")
                            for limitation in modelCard["limitation"]:
                                print(f"\t{limitation}")
                        if "tradeoff" in modelCard:
                            if not title:
                                print("Considerations\n")
                                title = True
                            print("Performance TradeOffs")
                            for tradeoff in modelCard["tradeoff"]:
                                print(f"\t{tradeoff}")
                        if "ethicalrisk" in modelCard:
                            if not title:
                                print("Considerations\n")
                                title = True
                            print("Ethical Considerations")
                            for consideration in modelCard["ethicalrisk"]:
                                print(
                                    f"\tName: {consideration[0]} Mitigation Strategy: {consideration[1]}"
                                )
                        if "fairness" in modelCard:
                            if not title:
                                print("Considerations\n")
                                title = True
                            print("Fairness Assessment")
                            for assessment in modelCard["fairness"]:
                                print(
                                    f"\tGroup at risk: {assessment[0]} Benefirs: {assessment[1]} Harms: {assessment[2]} Mitigation Strategy: {assessment[3]}"
                                )
                        if "property" in modelCard:
                            # Potentially multiple entries
                            print("Properties")
                            for property in modelCard["property"]:
                                print(f"\tName: {property[0]} Value: {property[1]}")

        else:
            print("No packages found")
    else:
        print("MLBOMs are only available for CycloneDX version 1.5 and greater")

except FileNotFoundError:
    print(f"{sys.argv[1]} not found")
