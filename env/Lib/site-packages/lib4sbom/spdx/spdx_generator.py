# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import uuid
from datetime import datetime

from lib4sbom.license import LicenseScanner
from lib4sbom.version import VERSION


class SPDXGenerator:
    """
    Generate SPDX Tag/Value SBOM.
    """

    SPDX_VERSION = "SPDX-2.3"
    DATA_LICENSE = "CC0-1.0"
    SPDX_NAMESPACE = "http://spdx.org/spdxdocs/"
    SPDX_PREAMBLE = "SPDXRef-"
    SPDX_PROJECT_ID = f"{SPDX_PREAMBLE}DOCUMENT"
    PACKAGE_PREAMBLE = f"{SPDX_PREAMBLE}Package-"
    FILE_PREAMBLE = f"{SPDX_PREAMBLE}File-"
    LICENSE_PREAMBLE = "LicenseRef-"

    def __init__(
        self,
        validate_license: True,
        spdx_format="tag",
        application="lib4sbom",
        version=VERSION,
    ):
        self.package_id = 0
        self.validate_license = validate_license
        self.license = LicenseScanner()
        self.relationship = []
        self.format = spdx_format
        self.application = application
        self.application_version = version
        if self.format == "tag":
            self.doc = []
        else:
            self.doc = {}
            self.component = []
            self.file_component = []
            self.relationships = []
            self.licenses = []
        self.include_purl = False
        self.debug = os.getenv("LIB4SBOM_DEBUG") is not None
        # Can specify version of SPDX through environment variable
        self.spdx_version = os.getenv("LIB4SBOM_SPDX_VERSION")
        # Check valid version
        self.spec_version(self.spdx_version)
        if self.spdx_version is None:
            self.spdx_version = self.SPDX_VERSION
        self.license_info = []
        self.license_id = 1

    def show(self, message):
        self.doc.append(message)

    def getBOM(self):
        if self.format != "tag":
            # Add subcomponents to SBOM
            if len(self.licenses) > 0:
                self.doc["hasExtractedLicensingInfos"] = self.licenses
            if len(self.file_component) > 0:
                self.doc["files"] = self.file_component
            self.doc["packages"] = self.component
            self.doc["relationships"] = self.relationships
        return self.doc

    def getRelationships(self):
        return self.relationship

    def generateTag(self, tag, value):
        if value is not None:
            self.show(tag + ": " + value)
        elif self.debug:
            print(f"[ERROR] with value for {tag}")

    def generateComment(self, comment):
        self.show("##### " + comment)

    def generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def spec_version(self, version):
        if version in ["SPDX-2.2", "SPDX-2.3"]:
            self.spdx_version = version
        else:
            self.spdx_version = None

    def _uuid(self, id=None):
        if id is None:
            return str(uuid.uuid4())
        return id

    def generateTagDocumentHeader(self, project_name, uuid=None):
        # Geerate SPDX Document Header
        self.generateTag("SPDXVersion", self.spdx_version)
        self.generateTag("DataLicense", self.DATA_LICENSE)
        self.generateTag("SPDXID", self.SPDX_PROJECT_ID)
        # Project name mustn't have spaces in. Covert spaces to '-'
        self.generateTag("DocumentName", project_name.replace(" ", "-"))
        self.generateTag(
            "DocumentNamespace",
            self.SPDX_NAMESPACE
            + project_name.replace(" ", "-")
            + "-"
            + self._uuid(uuid),
        )
        self.generateTag("LicenseListVersion", self.license.get_license_version())
        self.generateTag(
            "Creator: Tool", self.application + "-" + self.application_version
        )
        self.generateTag("Created", self.generateTime())
        self.generateTag(
            "CreatorComment",
            self._text("This document has been automatically generated."),
        )
        return self.SPDX_PROJECT_ID

    def generateJSONDocumentHeader(self, project_name, uuid=None):
        # Generate SPDX Document Header
        self.doc["SPDXID"] = self.SPDX_PROJECT_ID
        self.doc["spdxVersion"] = self.spdx_version
        creation_info = dict()
        creation_info["comment"] = "This document has been automatically generated."
        creation_info["creators"] = [
            "Tool: " + self.application + "-" + self.application_version
        ]
        creation_info["created"] = self.generateTime()
        creation_info["licenseListVersion"] = self.license.get_license_version()
        self.doc["creationInfo"] = creation_info
        # Project name mustn't have spaces in. Covert spaces to '-'
        self.doc["name"] = project_name.replace(" ", "-")
        self.doc["dataLicense"] = self.DATA_LICENSE
        self.doc["documentNamespace"] = (
            self.SPDX_NAMESPACE
            + project_name.replace(" ", "-")
            + "-"
            + self._uuid(uuid)
        )
        return self.SPDX_PROJECT_ID

    def generateDocumentHeader(self, project_name, uuid=None):
        # Assume a new document being created
        if self.format == "tag":
            self.doc = []
            return self.generateTagDocumentHeader(project_name, uuid)
        else:
            self.doc = {}
            self.component = []
            self.file_component = []
            self.relationships = []
            return self.generateJSONDocumentHeader(project_name, uuid)

    def package_ident(self, id):
        # Only add preamble if not parent document
        if id != self.SPDX_PROJECT_ID:
            spdx_id = ""
            # SPDX id can only contain letters, numbers, ., and/or -.
            for i in id:
                if i.isalnum():
                    spdx_id = spdx_id + i
                elif i in [".", "-"]:
                    spdx_id = spdx_id + i
                else:
                    # Invalid charcters are replaced
                    spdx_id = spdx_id + "-"
            # Check preamble not present
            if spdx_id.startswith(self.SPDX_PREAMBLE):
                return spdx_id
            return self.PACKAGE_PREAMBLE + spdx_id
        return str(id)

    def file_ident(self, id):
        # Only add preamble if not parent document
        if id != self.SPDX_PROJECT_ID:
            return self.FILE_PREAMBLE + str(id).replace(" ", "-").replace("_", "-")
        return str(id)

    def license_ref(self):
        return f"LicenseRef-{self.license_id}"

    def license_ident(self, license):
        if len(license) == 0:
            return "NOASSERTION"
        elif self.validate_license:
            if license != "UNKNOWN":
                derived_license = self.license.find_license(license)
                if derived_license != "UNKNOWN":
                    return derived_license
                # Not an SPDX License id
            return "NOASSERTION"
        else:
            # No validation
            return license

    def _text(file, text_item):
        if text_item not in ["NONE", "NOASSERTION"]:
            return f"<text>{text_item}</text>"
        return text_item

    def _file_name(self, name):
        # ensure name is a relative filename
        if name.startswith("/"):
            return name
        elif name.startswith("./"):
            return name
        else:
            return "./" + name

    def generateTagPackageDetails(
        self, package, id, package_info, parent_id, relationship
    ):
        self.generateComment("\n")
        self.generateTag("PackageName", package)
        package_id = self.package_ident(id)
        self.generateTag("SPDXID", package_id)
        if "version" in package_info:
            version = package_info["version"]
            self.generateTag("PackageVersion", version)
        elif self.debug:
            print(f"[WARNING] **** version missing for {package}")
        if "type" in package_info:
            # Handle SPDX mismatch of - and _ in OPERATING-SYSTEM
            self.generateTag(
                "PrimaryPackagePurpose", package_info["type"].upper().replace("-", "_")
            )
        else:
            self.generateTag("PrimaryPackagePurpose", "LIBRARY")
        if "supplier" in package_info:
            if package_info["supplier_type"] != "UNKNOWN":
                self.generateTag(
                    "PackageSupplier",
                    package_info["supplier_type"] + ": " + package_info["supplier"],
                )
            else:
                self.generateTag("PackageSupplier", "NOASSERTION")
        if "originator" in package_info:
            if package_info["originator_type"] != "UNKNOWN":
                self.generateTag(
                    "PackageOriginator",
                    package_info["originator_type"] + ": " + package_info["originator"],
                )
            else:
                self.generateTag("PackageOriginator", "NOASSERTION")
        self.generateTag(
            "PackageDownloadLocation",
            package_info.get("downloadlocation", "NOASSERTION"),
        )
        files_analysed = package_info.get("filesanalysis", False)
        self.generateTag("FilesAnalyzed", str(files_analysed).lower())
        if "filename" in package_info:
            self.generateTag("PackageFileName", package_info["filename"])
        if "homepage" in package_info:
            self.generateTag("PackageHomePage", package_info["homepage"])
        if "checksum" in package_info:
            # Potentially multiple entries
            for checksum in package_info["checksum"]:
                self.generateTag("PackageChecksum", checksum[0] + ": " + checksum[1])
        if "sourceinfo" in package_info:
            self.generateTag(
                "PackageSourceInfo", self._text(package_info["sourceinfo"])
            )
        if "licensedeclared" in package_info:
            if "licensename" in package_info:
                # User defined license
                self.generateTag("PackageLicenseDeclared", self.license_ref())
                self.license_info.append(
                    {
                        "id": self.license_ref(),
                        "name": package_info["licensename"],
                        "text": package_info["licensedeclared"],
                    }
                )
                self.license_id = self.license_id + 1
            else:
                self.generateTag(
                    "PackageLicenseDeclared",
                    self.license_ident(package_info["licensedeclared"]),
                )
        if "licenseconcluded" in package_info:
            self.generateTag(
                "PackageLicenseConcluded",
                self.license_ident(package_info["licenseconcluded"]),
            )
        if "licensecomments" in package_info:
            self.generateTag(
                "PackageLicenseComments",
                self._text(package_info["licensecomments"]),
            )
        if files_analysed:
            # Only if files have been analysed
            if "licenseinfoinfiles" in package_info:
                for info in package_info["licenseinfoinfiles"]:
                    self.generateTag(
                        "PackageLicenseInfoFromFiles",
                        self.license_ident(info),
                    )
        if "copyrighttext" in package_info:
            self.generateTag(
                "PackageCopyrightText", self._text(package_info["copyrighttext"])
            )
        else:
            self.generateTag("PackageCopyrightText", "NOASSERTION")
        if "description" in package_info:
            self.generateTag(
                "PackageDescription", self._text(package_info["description"])
            )
        if "comment" in package_info:
            self.generateTag("PackageComment", self._text(package_info["comment"]))
        if "summary" in package_info:
            self.generateTag("PackageSummary", self._text(package_info["summary"]))
        if "attribution" in package_info:
            # Potentially multiple entries
            for attribution in package_info["attribution"]:
                self.generateTag("PackageAttributionText", self._text(attribution))
        if "externalreference" in package_info:
            # Potentially multiple entries
            for reference in package_info["externalreference"]:
                if reference[0] in ["SECURITY", "PACKAGE-MANAGER", "PACKAGE_MANAGER"]:
                    self.generateTag(
                        "ExternalRef",
                        reference[0] + " " + reference[1] + " " + reference[2],
                    )

    def generateJSONPackageDetails(
        self, package, id, package_info, parent_id, relationship
    ):
        component = dict()
        package_id = self.package_ident(id)
        component["SPDXID"] = package_id
        component["name"] = package
        if "version" in package_info:
            version = package_info["version"]
            component["versionInfo"] = version
        elif self.debug:
            print(f"[WARNING] **** version missing for {package}")
        if "type" in package_info:
            component["primaryPackagePurpose"] = (
                package_info["type"].upper().replace("-", "_")
            )
        else:
            component["primaryPackagePurpose"] = "LIBRARY"
        if "supplier" in package_info:
            if package_info["supplier_type"] != "UNKNOWN":
                component["supplier"] = (
                    package_info["supplier_type"] + ": " + package_info["supplier"]
                )
            else:
                component["supplier"] = "NOASSERTION"
        if "originator" in package_info:
            if package_info["originator_type"] != "UNKNOWN":
                component["originator"] = (
                    package_info["originator_type"] + ": " + package_info["originator"]
                )
            else:
                component["originator"] = "NOASSERTION"
        component["downloadLocation"] = package_info.get(
            "downloadlocation", "NOASSERTION"
        )
        files_analysed = package_info.get("filesanalysis", False)
        component["filesAnalyzed"] = files_analysed
        if "filename" in package_info:
            component["packageFileName"] = package_info["filename"]
        if "homepage" in package_info:
            component["homepage"] = package_info["homepage"]
        if "checksum" in package_info:
            # Potentially multiple entries
            for checksum in package_info["checksum"]:
                checksum_entry = dict()
                checksum_entry["algorithm"] = checksum[0]
                checksum_entry["checksumValue"] = checksum[1]
                if "checksums" in component:
                    component["checksums"].append(checksum_entry)
                else:
                    component["checksums"] = [checksum_entry]
        if "sourceinfo" in package_info:
            component["sourceInfo"] = package_info["sourceinfo"]
        if "licenseconcluded" in package_info:
            component["licenseConcluded"] = self.license_ident(
                package_info["licenseconcluded"]
            )
        if "licensedeclared" in package_info:
            if "licensename" in package_info:
                # User defined license
                component["licenseDeclared"] = self.license_ref()
                self.license_info.append(
                    {
                        "id": self.license_ref(),
                        "name": package_info["licensename"],
                        "text": package_info["licensedeclared"],
                    }
                )
                self.license_id = self.license_id + 1
            else:
                component["licenseDeclared"] = self.license_ident(
                    package_info["licensedeclared"]
                )
        if "licensecomments" in package_info:
            component["licenseComments"] = package_info["licensecomments"]
        if files_analysed:
            # Only if files have been analysed
            if "licenseinfoinfiles" in package_info:
                for info in package_info["licenseinfoinfile"]:
                    if "licenseInfoInFiles" in component:
                        component["licenseInfoInFiles"].append(self.license_ident(info))
                    else:
                        component["licenseInfoInFiles"] = [self.license_ident(info)]
        component["copyrightText"] = package_info.get("copyrighttext", "NOASSERTION")
        if "description" in package_info:
            component["description"] = package_info["description"]
        if "comment" in package_info:
            component["comment"] = package_info["comment"]
        if "summary" in package_info:
            component["summary"] = package_info["summary"]
        if "attribution" in package_info:
            # Potentially multiple entries
            for attribution in package_info["attribution"]:
                attribution_data = dict()
                # Unclear what field should be from SPDX specification
                attribution_data["value"] = attribution
                if "attribution" in component:
                    component["attribution"].append(attribution_data)
                else:
                    component["attribution"] = [attribution_data]
        if "externalreference" in package_info:
            # Potentially multiple entries
            for reference in package_info["externalreference"]:
                if reference[0] in ["SECURITY", "PACKAGE-MANAGER", "PACKAGE_MANAGER"]:
                    reference_data = dict()
                    reference_data["referenceCategory"] = reference[0]
                    reference_data["referenceType"] = reference[1]
                    reference_data["referenceLocator"] = reference[2]
                    if "externalRefs" in component:
                        component["externalRefs"].append(reference_data)
                    else:
                        component["externalRefs"] = [reference_data]
        self.component.append(component)

    def generateTagFileDetails(self, file, id, file_info, parent_id, relationship):
        self.generateComment("\n")
        self.generateTag("FileName", self._file_name(file))
        file_id = self.file_ident(id)
        self.generateTag("SPDXID", file_id)
        if "checksum" in file_info:
            # Potentially multiple entries
            for checksum in file_info["checksum"]:
                self.generateTag("FileChecksum", checksum[0] + ": " + checksum[1])
        if "filetype" in file_info:
            for type in file_info["filetype"]:
                self.generateTag("FileType", type)
        if "licenseconcluded" in file_info:
            self.generateTag(
                "LicenseConcluded", self.license_ident(file_info["licenseconcluded"])
            )
        if "licenseinfoinfile" in file_info:
            for info in file_info["licenseinfoinfile"]:
                self.generateTag("LicenseInfoInFile", self.license_ident(info))
        if "licensecomment" in file_info:
            self.generateTag("LicenseComments", self._text(file_info["licensecomment"]))
        if "copyrighttext" in file_info:
            self.generateTag(
                "FileCopyrightText", self._text(file_info["copyrighttext"])
            )
        if "comment" in file_info:
            self.generateTag("FileComment", self._text(file_info["comment"]))
        if "notice" in file_info:
            self.generateTag("FileNotice", self._text(file_info["notice"]))
        if "contributor" in file_info:
            for contributor in file_info["contributor"]:
                self.generateTag("FileContributor", contributor)

    def generateJSONFileDetails(self, file, id, file_info, parent_id, relationship):
        component = dict()
        file_id = self.file_ident(id)
        component["SPDXID"] = file_id
        component["fileName"] = self._file_name(file)
        if "copyrighttext" in file_info:
            component["copyrightText"] = file_info["copyrighttext"]
        if "licenseconcluded" in file_info:
            component["licenseConcluded"] = self.license_ident(
                file_info["licenseconcluded"]
            )
        if "filetype" in file_info:
            for type in file_info["filetype"]:
                if "fileTypes" in component:
                    component["fileTypes"].append(type)
                else:
                    component["fileTypes"] = [type]
        if "licenseinfoinfile" in file_info:
            for info in file_info["licenseinfoinfile"]:
                if "licenseInfoInFiles" in component:
                    component["licenseInfoInFiles"].append(self.license_ident(info))
                else:
                    component["licenseInfoInFiles"] = [self.license_ident(info)]
        if "licensecomment" in file_info:
            component["licenseComments"] = file_info["licensecomment"]
        if "checksum" in file_info:
            # Potentially multiple entries
            for checksum in file_info["checksum"]:
                checksum_entry = dict()
                checksum_entry["algorithm"] = checksum[0]
                checksum_entry["checksumValue"] = checksum[1]
                if "checksums" in component:
                    component["checksums"].append(checksum_entry)
                else:
                    component["checksums"] = [checksum_entry]
        if "comment" in file_info:
            component["fileComment"] = file_info["comment"]
        if "notice" in file_info:
            component["fileNotice"] = file_info["notice"]
        if "contributor" in file_info:
            for contributor in file_info["contributor"]:
                if "fileContributor" in component:
                    component["fileContributor"].append(contributor)
                else:
                    component["fileContributor"] = [contributor]
        self.file_component.append(component)

    def generateTagLicenseDetails(self, id, name, license_text, comment):
        self.generateTag("LicenseID", id)
        self.generateTag("LicenseName", name)
        if len(license_text) > 0:
            self.generateTag("ExtractedText", self._text(license_text))
        if len (comment) > 0:
            self.generateTag("LicenseComment", comment)

    def generateJSONLicenseDetails(self, id, name, license_text, comment):
        extractedlicense = {}
        if len(id) > 0:
            extractedlicense["licenseId"] = id
        if len(name) > 0:
            extractedlicense["name"] = name
        if len(license_text) > 0:
            extractedlicense["extractedText"] = license_text
        if len (comment) > 0:
            extractedlicense["comment"] = comment
        self.licenses.append(extractedlicense)

    def generatePackageDetails(
        self, package, id, package_info, parent_id, relationship
    ):
        if self.format == "tag":
            self.generateTagPackageDetails(
                package, id, package_info, parent_id, relationship
            )
        else:
            self.generateJSONPackageDetails(
                package, id, package_info, parent_id, relationship
            )

    def generateFileDetails(self, file, id, file_info, parent_id, relationship):
        if self.format == "tag":
            self.generateTagFileDetails(file, id, file_info, parent_id, relationship)
        else:
            self.generateJSONFileDetails(file, id, file_info, parent_id, relationship)

    def addLicenseDetails(self, user_licenses):
        for license in user_licenses:
            self.license_info.append(
                {
                    "id": license['id'],
                    "name": license.get("name",""),
                    "text": license.get("text",""),
                    "comment": license.get("comment", "")
                }
            )

    def generateLicenseDetails(self):
        for license_info in self.license_info:
            if self.format == "tag":
                self.generateComment("\n")
                self.generateTagLicenseDetails(
                    license_info.get("id",""), license_info.get("name",""), license_info["text"], license_info.get("comment","")
                )
            else:
                self.generateJSONLicenseDetails(
                    license_info.get("id",""), license_info.get("name",""), license_info["text"], license_info.get("comment","")
                )

    def generateRelationship(self, from_id, to_id, relationship_type):
        if (
            from_id != to_id
            and [from_id, to_id, relationship_type] not in self.relationship
        ):
            self.relationship.append([from_id, to_id, relationship_type])

    def showRelationship(self):
        self.relationship.sort()
        if self.format == "tag":
            self.generateComment("\n")
        for r in self.relationship:
            if self.format == "tag":
                self.generateTag("Relationship", f"{r[0]} {r[2].strip()} {r[1]}")
            else:
                relation = dict()
                relation["spdxElementId"] = r[0]
                relation["relatedSpdxElement"] = r[1]
                relation["relationshipType"] = r[2].strip()
                self.relationships.append(relation)
