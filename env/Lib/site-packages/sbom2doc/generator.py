# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import requests
from lib4sbom.data.document import SBOMDocument
from lib4sbom.license import LicenseScanner
from packageurl import PackageURL

from sbom2doc.docbuilder.consolebuilder import ConsoleBuilder
from sbom2doc.docbuilder.jsonbuilder import JSONBuilder
from sbom2doc.docbuilder.markdownbuilder import MarkdownBuilder
from sbom2doc.docbuilder.pdfbuilder import PDFBuilder
from sbom2doc.docbuilder.spreadsheetbuilder import SpreadsheetBuilder


def generate_document(format, sbom_parser, filename, outfile, include_license):
    # Get constituent components of the SBOM
    packages = sbom_parser.get_packages()
    files = sbom_parser.get_files()
    relationships = sbom_parser.get_relationships()
    services = sbom_parser.get_services()
    vulnerabilities = sbom_parser.get_vulnerabilities()
    document = SBOMDocument()
    document.copy_document(sbom_parser.get_document())
    license_info = LicenseScanner()

    # Select document builder based on format
    if format == "markdown":
        sbom_document = MarkdownBuilder()
    elif format == "json":
        sbom_document = JSONBuilder()
    elif format == "pdf":
        sbom_document = PDFBuilder()
    elif format == "excel":
        sbom_document = SpreadsheetBuilder()
    else:
        sbom_document = ConsoleBuilder()

    sbom_document.heading(1, "SBOM Summary")
    sbom_document.createtable(["Item", "Details"], [20, 35])
    sbom_document.addrow(["SBOM File", filename])
    sbom_document.addrow(["SBOM Type", document.get_type()])
    sbom_document.addrow(["Version", document.get_version()])
    sbom_document.addrow(["Name", document.get_name()])
    creator_identified = False
    creator = document.get_creator()
    # If creator is missing, will return None
    if creator is not None:
        for c in creator:
            creator_identified = True
            sbom_document.addrow(["Creator", f"{c[0]}:{c[1]}"])
    sbom_document.addrow(["Created", document.get_created()])
    sbom_document.addrow(["Files", str(len(files))])
    sbom_document.addrow(["Packages", str(len(packages))])
    sbom_document.addrow(["Relationships", str(len(relationships))])
    sbom_document.addrow(["Services", str(len(services))])
    sbom_document.addrow(["Vulnerabilities", str(len(vulnerabilities))])
    sbom_document.showtable(widths=[5, 9])
    creation_time = document.get_created() is not None

    files_valid = True
    packages_valid = True
    relationships_valid = len(relationships) > 0
    sbom_licenses = []
    sbom_components = []
    sbom_suppliers = []
    # Create an empty dictionary
    freq_licences = {}
    if len(files) > 0:
        sbom_document.heading(1, "File Summary")
        sbom_document.createtable(["Name", "Type", "License", "Copyright"])
        for file in files:
            # Minimum elements are ID, Name
            id = file.get("id", None)
            name = file.get("name", None)
            filetype = file.get("filetype", None)
            if filetype is not None:
                file_type = ", ".join(t for t in filetype)
            else:
                file_type = "NOT KNOWN"
            license = file.get("licenseconcluded", "NOT KNOWN")
            copyright = file.get("copyrighttext", "-")
            sbom_licenses.append(license)
            sbom_document.addrow([name, file_type, license, copyright])
            if id is None or name is None:
                files_valid = False
        sbom_document.showtable(widths=[3, 2, 4, 5])

    if len(packages) > 0:
        sbom_document.heading(1, "Package Summary")
        sbom_document.createtable(
            ["Name", "Version", "Type", "Supplier", "License"], [12, 8, 8, 8, 12]
        )
        for package in packages:
            # Minimum elements are ID, Name, Version, Supplier
            id = package.get("id", None)
            name = package.get("name", None)
            version = package.get("version", None)
            type = package.get("type", None)
            supplier = package.get("supplier", None)
            license = package.get("licenseconcluded", "NOT KNOWN")
            if license != "NOT KNOWN" and license_info.deprecated(license):
                license = f"{license} (Deprecated)"
            sbom_licenses.append(license)
            sbom_components.append(type)
            if supplier is not None:
                sbom_suppliers.append(supplier)
            sbom_document.addrow([name, version, type, supplier, license])
            if (
                id is None
                or name is None
                or version is None
                or supplier is None
                or supplier == "NOASSERTION"
            ):
                packages_valid = False
        sbom_document.showtable(widths=[5, 2, 2, 5])

        # Too much information so second table required
        sbom_document.paragraph("")
        sbom_document.createtable(
            ["Name", "Version", "Ecosystem", "Download", "Copyright"], [12, 8, 5, 8, 7]
        )
        for package in packages:
            name = package.get("name", None)
            version = package.get("version", None)
            external_info = package.get("externalreference", None)
            ecosystem = "-"
            if external_info is not None:
                for reference in external_info:
                    if reference[1] == "purl":
                        try:
                            purl = PackageURL.from_string(reference[2]).to_dict()
                            ecosystem = purl["type"]
                        except ValueError:
                            ecosystem = "INVALID"
                        break
            download = package.get("downloadlocation", "NOT KNOWN")
            copyright = package.get("copyrighttext", "-")
            sbom_document.addrow([name, version, ecosystem, download, copyright])
        sbom_document.showtable(widths=[5, 2, 2, 2, 2])

        sbom_document.heading(1, "Component Type Summary")
        sbom_document.createtable(["Type", "Count"], [25, 6])
        #
        # Create an empty dictionary
        freq = {}
        for items in sorted(sbom_components):
            freq[items] = sbom_components.count(items)
        for key, value in freq.items():
            sbom_document.addrow([key, str(value)])
        sbom_document.showtable(widths=[10, 4])

        sbom_document.heading(1, "License Summary")
        sbom_document.createtable(["License", "Count"], [25, 6])
        #
        for items in sorted(sbom_licenses):
            freq_licences[items] = sbom_licenses.count(items)
        for key, value in freq_licences.items():
            sbom_document.addrow([key, str(value)])
        sbom_document.showtable(widths=[10, 4])

        sbom_document.heading(1, "Supplier Summary")
        sbom_document.createtable(["Supplier", "Count"], [25, 6])
        #
        # Create an empty dictionary
        freq_suppliers = {}
        for items in sorted(sbom_suppliers):
            freq_suppliers[items] = sbom_suppliers.count(items)
        for key, value in freq_suppliers.items():
            sbom_document.addrow([key, str(value)])
        sbom_document.showtable(widths=[10, 4])

    sbom_document.heading(1, "NTIA Summary")
    sbom_document.createtable(["Element", "Status"])
    sbom_document.addrow(["All file information provided?", str(files_valid)])
    sbom_document.addrow(["All package information provided?", str(packages_valid)])
    sbom_document.addrow(["Creator identified?", str(creator_identified)])
    sbom_document.addrow(["Creation time identified?", str(creation_time)])
    sbom_document.addrow(
        ["Dependency relationships provided?", str(relationships_valid)]
    )
    sbom_document.showtable(widths=[10, 4])

    valid_sbom = (
        files_valid
        and packages_valid
        and creator_identified
        and creation_time
        and relationships_valid
    )
    sbom_document.paragraph(f"NTIA conformant {valid_sbom}")

    if len(services) > 0:
        sbom_document.heading(1, "Services Summary")
        sbom_document.createtable(["Name", "Description", "Authenticated", "Data"])
        for service in services:
            id = service.get("id", None)
            name = service.get("name", "")
            description = service.get("description", "")
            if service.get("authenticated") is None:
                authenticated = "Not defined"
            else:
                authenticated = str(service.get("authenticated"))
            # dataitems = service.get("data", "")
            sbom_document.addrow([name, description, authenticated, ""])
        sbom_document.showtable(widths=[3, 2, 4, 5])

    if len(vulnerabilities) > 0:
        sbom_document.heading(1, "Vulnerabilities Summary")
        sbom_document.createtable(["Name", "Id", "Status", "Copyright"])
        for vulnerability in vulnerabilities:
            pass

    if include_license and len(freq_licences) > 0:
        sbom_document.pagebreak()
        sbom_document.heading(1, "License Text")
        for key, value in freq_licences.items():
            # Ignore undefined licenses or expressions
            if key == "NOASSERTION" or license_info.license_expression(key):
                continue
            license_url = f"https://spdx.org/licenses/{key}.json"
            try:
                license_text = requests.get(license_url).json()
                if license_text.get("licenseText") is not None:
                    sbom_document.heading(2, key, number=False)
                    sbom_document.paragraph(license_text["licenseText"])
            except requests.exceptions.RequestException:
                sbom_document.heading(2, key, number=False)
                sbom_document.paragraph("Unable to find license text.")

    sbom_document.publish(outfile)
