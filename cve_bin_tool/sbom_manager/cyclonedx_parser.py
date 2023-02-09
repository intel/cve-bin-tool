# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json

import defusedxml.ElementTree as ET

from cve_bin_tool.validator import validate_cyclonedx


class CycloneParser:
    def __init__(self, validate: bool = True):
        self.validate = validate
        self.components_supported = [
            "library",
            "application",
            "operating-system",
            "framework",
        ]

    def parse(self, sbom_file: str) -> list[list[str]]:
        """parses CycloneDX BOM file extracting package name and version"""
        # Supported cyclonedx_type = [".json", ".xml"]
        if sbom_file.endswith("json"):
            return self.parse_cyclonedx_json(sbom_file)
        elif sbom_file.endswith(".xml"):
            return self.parse_cyclonedx_xml(sbom_file)
        else:
            return []

    def parse_cyclonedx_json(self, sbom_file: str) -> list[list[str]]:
        """parses CycloneDX JSON BOM file extracting package name and version"""
        data = json.load(open(sbom_file))
        modules: list[list[str]] = []
        for d in data["components"]:
            if d["type"] in self.components_supported:
                package = d["name"]
                version = d["version"]
                modules.append([package, version])

        return modules

    def parse_cyclonedx_xml(self, sbom_file: str) -> list[list[str]]:
        """parses CycloneDX XML BOM file extracting package name and version"""
        modules: list[list[str]] = []
        if self.validate and not validate_cyclonedx(sbom_file):
            return modules
        tree = ET.parse(sbom_file)
        # Find root element
        root = tree.getroot()
        # Extract schema
        schema = root.tag[: root.tag.find("}") + 1]
        # schema = '{http://cyclonedx.org/schema/bom/1.3}'
        print("Schema", schema)
        for components in root.findall(schema + "components"):
            for component in components.findall(schema + "component"):
                # Only for application and library components
                if component.attrib["type"] in self.components_supported:
                    component_name = component.find(schema + "name")
                    if component_name is None:
                        raise KeyError(f"Could not find package in {component}")
                    package = component_name.text
                    if package is None:
                        raise KeyError(f"Could not find package in {component}")
                    component_version = component.find(schema + "version")
                    if component_version is None:
                        raise KeyError(f"Could not find version in {component}")
                    version = component_version.text
                    if version is not None:
                        modules.append([package, version])
        return modules


if __name__ == "__main__":
    import sys

    cyclone = CycloneParser()
    file = sys.argv[1]
    # cyclone.parse_cyclonedx_json(file)
    cyclone.parse_cyclonedx_xml(file)
    print("And again....")
    # Should get same results....
    cyclone.parse(file)
