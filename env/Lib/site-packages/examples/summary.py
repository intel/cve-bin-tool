# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to parse a SBOM and
### produce a summary of its contents

import sys

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.service import SBOMService
from lib4sbom.parser import SBOMParser

test_parser = SBOMParser()
# Load SBOM
try:
    test_parser.parse_file(sys.argv[1])

    # What type of SBOM
    document = SBOMDocument()
    document.copy_document(test_parser.get_document())

    packages = test_parser.get_packages()
    files = test_parser.get_files()
    services = test_parser.get_services()
    vulnerabilities = test_parser.get_vulnerabilities()
    print("Summary")
    print("=" * len("summary"))
    print(f"SBOM Type    {document.get_type()}")
    print(f"Version      {document.get_version()}")
    print(f"Name         {document.get_name()}")
    print()
    print(f"Files        {len(files)}")
    if len(files) > 0:
        print(f"\n{'Name':50} {'Type':20}")
        print("-" * 70)
        for file in files:
            file_types = file.get("filetype", ["NOT DEFINED"])
            for file_type in file_types:
                print(f"{file['name'][:50]:50} {file_type:20}")
    print(f"\nPackages     {len(packages)}")
    if len(packages) > 0:
        print(f"\n{'Name':30} {'Version':15} {'Type':20}")
        print("-" * 70)
        thepackage = SBOMPackage()
        for package in packages:
            thepackage.copy_package(package)
            print(
                f"{package['name']:30} {package.get('version','MISSING'):15} {package['type']:20}"
            )
            print(f"PURL {thepackage.get_purl()}")
            print(f"CPE {thepackage.get_cpe()}")
    print(f"\nVulnerabilities    {len(vulnerabilities)}")
    if len(vulnerabilities) > 0:
        print("-" * 70)
        for vuln in vulnerabilities:
            print(vuln)
    print(f"\nServices     {len(services)}")
    if len(services) > 0:
        print(f"\n{'Name':30} {'Version':15} {'Id':20}")
        print("-" * 70)
        theservice = SBOMService()
        for service in services:
            theservice.copy_service(service)
            print(
                f"{service['name']:30} {service.get('version','MISSING'):15} {service['id']:20}"
            )
            print(f"Endpoints {theservice.get_value('endpoints')}")

except FileNotFoundError:
    print(f"{sys.argv[1]} not found")
