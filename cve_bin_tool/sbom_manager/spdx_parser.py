# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
import re

import defusedxml.ElementTree as ET
import yaml

from cve_bin_tool.log import LOGGER
from cve_bin_tool.validator import validate_spdx


class SPDXParser:
    def __init__(self, validate: bool = True):
        self.validate = validate

    def parse(self, sbom_file: str) -> list[list[str]]:
        """parses SPDX BOM file extracting package name and version"""
        # Supported spdx_type = [".spdx", ".spdx.json", ".spdx.rdf", ".spdx.xml" , ".spdx.yaml", ".spdx.yml" ]
        if sbom_file.endswith(".spdx"):
            return self.parse_spdx_tag(sbom_file)
        elif sbom_file.endswith(".spdx.json"):
            return self.parse_spdx_json(sbom_file)
        elif sbom_file.endswith(".spdx.rdf"):
            return self.parse_spdx_rdf(sbom_file)
        elif sbom_file.endswith(".spdx.xml"):
            return self.parse_spdx_xml(sbom_file)
        elif sbom_file.endswith((".spdx.yaml", "spdx.yml")):
            return self.parse_spdx_yaml(sbom_file)
        else:
            return []

    def parse_spdx_tag(self, sbom_file: str) -> list[list[str]]:
        """parses SPDX tag value BOM file extracting package name and version"""
        with open(sbom_file) as f:
            lines = f.readlines()
        modules: list[list[str]] = []
        package = ""
        for line in lines:
            line_elements = line.split(":")
            if line_elements[0] == "PackageName":
                package = line_elements[1].strip().rstrip("\n")
                version = None
            if line_elements[0] == "PackageVersion":
                # Version may contain :
                version = line[16:].strip().rstrip("\n")
                version = version.split("-")[0]
                version = version.split("+")[0]
                modules.append([package, version])

        return modules

    def parse_spdx_json(self, sbom_file: str) -> list[list[str]]:
        """parses SPDX JSON BOM file extracting package name and version"""
        data = json.load(open(sbom_file))
        modules: list[list[str]] = []
        for d in data["packages"]:
            package = d["name"]
            try:
                version = d["versionInfo"]
                modules.append([package, version])
            except KeyError as e:
                LOGGER.debug(e, exc_info=True)

        return modules

    def parse_spdx_rdf(self, sbom_file: str) -> list[list[str]]:
        """parses SPDX RDF BOM file extracting package name and version"""
        with open(sbom_file) as f:
            lines = f.readlines()
        modules: list[list[str]] = []
        package = ""
        for line in lines:
            try:
                if line.strip().startswith("<spdx:name>"):
                    stripped_line = line.strip().rstrip("\n")
                    package_match = re.search(
                        "<spdx:name>(.+?)</spdx:name>", stripped_line
                    )
                    if not package_match:
                        raise KeyError(f"Could not find package in {stripped_line}")
                    package = package_match.group(1)
                    version = None
                elif line.strip().startswith("<spdx:versionInfo>"):
                    stripped_line = line.strip().rstrip("\n")
                    version_match = re.search(
                        "<spdx:versionInfo>(.+?)</spdx:versionInfo>", stripped_line
                    )
                    if not version_match:
                        raise KeyError(f"Could not find version in {stripped_line}")
                    version = version_match.group(1)
                    modules.append([package, version])
            except KeyError as e:
                LOGGER.debug(e, exc_info=True)

        return modules

    def parse_spdx_yaml(self, sbom_file: str) -> list[list[str]]:
        """parses SPDX YAML BOM file extracting package name and version"""
        data = yaml.safe_load(open(sbom_file))

        modules: list[list[str]] = []
        for d in data["packages"]:
            package = d["name"]
            try:
                version = d["versionInfo"]
                modules.append([package, version])
            except KeyError as e:
                LOGGER.debug(e, exc_info=True)

        return modules

    def parse_spdx_xml(self, sbom_file: str) -> list[list[str]]:
        """parses SPDX XML BOM file extracting package name and version"""
        # XML is experimental in SPDX 2.2
        modules: list[list[str]] = []
        if self.validate and not validate_spdx(sbom_file):
            return modules
        tree = ET.parse(sbom_file)
        # Find root element
        root = tree.getroot()
        # Extract schema
        schema = root.tag[: root.tag.find("}") + 1]

        for component in root.findall(schema + "packages"):
            try:
                package_match = component.find(schema + "name")
                if package_match is None:
                    raise KeyError(f"Could not find package in {component}")
                package = package_match.text
                if package is None:
                    raise KeyError(f"Could not find package in {component}")
                version_match = component.find(schema + "versionInfo")
                if version_match is None:
                    raise KeyError(f"Could not find version in {component}")
                version = version_match.text
                if version is None:
                    raise KeyError(f"Could not find version in {component}")
                modules.append([package, version])
            except KeyError as e:
                LOGGER.debug(e, exc_info=True)

        return modules


if __name__ == "__main__":
    import sys

    spdx = SPDXParser()
    file = sys.argv[1]
    # spdx.parse_TAG(file)
    # print(spdx.parse_sbom(file))
    # spdx.parse_spdx_tag(file)
    # spdx.parse_spdx_rdf(file)
    # spdx.parse_spdx_json(file)
    # spdx.parse_spdx_yaml(file)
    spdx.parse_spdx_xml(file)
    print("And again....")
    # Should get same results....
    spdx.parse(file)
