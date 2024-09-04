# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
from logging import Logger
from pathlib import Path
from typing import Dict, List, Optional

from lib4sbom.data.vulnerability import Vulnerability
from lib4vex.generator import VEXGenerator

from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import CVEData, ProductInfo, Remarks


class VEXGenerate:
    analysis_state = {
        "cyclonedx": {
            Remarks.NewFound: "in_triage",
            Remarks.Unexplored: "in_triage",
            Remarks.Confirmed: "exploitable",
            Remarks.Mitigated: "resolved",
            Remarks.FalsePositive: "false_positive",
            Remarks.NotAffected: "not_affected",
        },
        "csaf": {
            Remarks.NewFound: "under_investigation",
            Remarks.Unexplored: "under_investigation",
            Remarks.Confirmed: "known_affected",
            Remarks.Mitigated: "fixed",
            Remarks.FalsePositive: "known_not_affected",
            Remarks.NotAffected: "known_not_affected",
        },
        "openvex": {
            Remarks.NewFound: "under_investigation",
            Remarks.Unexplored: "under_investigation",
            Remarks.Confirmed: "affected",
            Remarks.Mitigated: "fixed",
            Remarks.FalsePositive: "not_affected",
            Remarks.NotAffected: "not_affected",
        },
    }

    def __init__(
        self,
        product: str,
        release: str,
        vendor: str,
        filename: str,
        vextype: str,
        all_cve_data: Dict[ProductInfo, CVEData],
        revision_reason: str = "",
        sbom_serial_number: str = "",
        sbom: Optional[str] = None,
        logger: Optional[Logger] = None,
        validate: bool = True,
    ):
        self.product = product
        self.release = release
        self.vendor = vendor
        self.revision_reason = revision_reason
        self.sbom = sbom
        self.filename = filename
        self.vextype = vextype
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.validate = validate
        self.all_cve_data = all_cve_data
        self.sbom_serial_number = sbom_serial_number

    def generate_vex(self) -> None:
        """
        Generates VEX code based on the specified VEX type.

        Returns:
            None
        """
        author = "Unknown Author"
        if self.vendor:
            author = self.vendor
        vexgen = VEXGenerator(vex_type=self.vextype, author=author)
        kwargs = {"name": self.product, "release": self.release}
        if self.sbom:
            kwargs["sbom"] = self.sbom
        vexgen.set_product(**kwargs)
        if not self.filename:
            self.logger.info(
                "No filename defined, Generating a new filename with Default Naming Convention"
            )
            self.filename = self.__generate_vex_filename()
        if Path(self.filename).is_file():
            self.logger.info(f"Updating the vex file: {self.filename}")

        vexgen.generate(
            project_name=self.product,
            vex_data=self.__get_vulnerabilities(),
            metadata=self.__get_metadata(),
            filename=self.filename,
        )

    def __generate_vex_filename(self) -> str:
        """
        Generates a VEX filename based on the current date and time.

        Returns:
            str: The generated VEX filename.
        """
        filename = (
            Path.cwd()
            / f"{self.product}_{self.release}_{self.vendor}_{self.vextype}.json"
        )
        return str(filename)

    def __get_metadata(self) -> Dict:
        metadata = {}
        if self.vextype == "cyclonedx":
            if self.product:
                metadata["id"] = f"{self.product.upper()}-VEX"
        elif self.vextype == "csaf":
            if self.product and self.release and self.vendor:
                metadata["id"] = f"{self.product.upper()}-{self.release}-VEX"
                metadata["supplier"] = self.vendor
        elif self.vextype == "openvex":
            if self.vendor:
                metadata["author"] = self.vendor
                metadata["supplier"] = self.vendor
        if self.revision_reason:
            metadata["revision_reason"] = self.revision_reason

        return metadata

    def __get_vulnerabilities(self) -> List[Vulnerability]:
        """
        Retrieves a list of vulnerabilities.

        Returns:
            A list of Vulnerability objects representing the vulnerabilities.
        """
        vulnerabilities = []
        for product_info, cve_data in self.all_cve_data.items():
            vendor, product, version, _, purl = product_info
            for cve in cve_data["cves"]:
                if isinstance(cve, str):
                    continue
                vulnerability = Vulnerability(validation=self.vextype)
                vulnerability.initialise()
                vulnerability.set_name(product)
                vulnerability.set_release(version)
                vulnerability.set_id(cve.cve_number)
                vulnerability.set_description(cve.description)
                vulnerability.set_comment(cve.comments)
                vulnerability.set_status(self.analysis_state[self.vextype][cve.remarks])
                if cve.justification:
                    vulnerability.set_justification(cve.justification)
                if cve.response:
                    vulnerability.set_value("remediation", cve.response[0])
                detail = (
                    f"{cve.remarks.name}: {cve.comments}"
                    if cve.comments
                    else cve.remarks.name
                )
                # more details will be added using set_value()
                if purl is None:
                    purl = f"pkg:generic/{vendor}/{product}@{version}"
                bom_version = 1
                if self.sbom_serial_number != "":
                    ref = f"urn:cdx:{self.sbom_serial_number}/{bom_version}#{purl}"
                else:
                    ref = f"urn:cbt:{bom_version}/{vendor}#{product}:{version}"

                vulnerability.set_value("purl", str(purl))
                vulnerability.set_value("bom_link", ref)
                vulnerability.set_value("action", detail)
                vulnerability.set_value("source", cve.data_source)
                vulnerability.set_value("updated", cve.last_modified)
                # vulnerability.show_vulnerability()
                vulnerabilities.append(vulnerability.get_vulnerability())
        self.logger.debug(f"Vulnerabilities: {vulnerabilities}")
        return vulnerabilities
