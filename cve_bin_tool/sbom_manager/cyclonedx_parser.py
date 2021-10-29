# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

import json
from typing import List

import defusedxml.ElementTree as ET


class CycloneParser:
    def __init__(self):
        pass

    def parse(self, sbom_file: str) -> List[List[str]]:
        """parses CycloneDX BOM file extracting package name and version"""
        # Supported cyclonedx_type = [".json", ".xml"]
        if sbom_file.endswith("json"):
            return self.parse_cyclonedx_json(sbom_file)
        elif sbom_file.endswith(".xml"):
            return self.parse_cyclonedx_xml(sbom_file)
        else:
            return []

    def parse_cyclonedx_json(self, sbom_file: str) -> List[List[str]]:
        """parses CycloneDX JSON BOM file extracting package name and version"""
        data = json.load(open(sbom_file))
        modules: List[List[str]] = []
        for d in data["components"]:
            if d["type"] == "library":
                package = d["name"]
                version = d["version"]
                modules.append([package, version])

        return modules

    def parse_cyclonedx_xml(self, sbom_file: str) -> List[List[str]]:
        """parses CycloneDX XML BOM file extracting package name and version"""

        tree = ET.parse(sbom_file)
        # Find root element
        root = tree.getroot()
        # Extract schema
        schema = root.tag[: root.tag.find("}") + 1]
        # schema = '{http://cyclonedx.org/schema/bom/1.3}'

        modules: List[List[str]] = []
        for components in root.findall(schema + "components"):
            for component in components.findall(schema + "component"):
                # Only if library....
                if component.attrib["type"] == "library":
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
                    if version is None:
                        raise KeyError(f"Could not find version in {component}")
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
