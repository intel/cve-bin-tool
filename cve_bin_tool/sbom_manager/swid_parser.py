# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import List

import defusedxml.ElementTree as ET


class SWIDParser:
    def __init__(self):
        pass

    def parse(self, sbom_file: str) -> List[List[str]]:
        """parses SWID XML BOM file extracting package name and version"""

        tree = ET.parse(sbom_file)
        # Find root element
        root = tree.getroot()
        # Extract schema
        schema = root.tag[: root.tag.find("}") + 1]
        # schema = '{http://standards.iso.org/iso/19770/-2/2015/schema.xsd}'

        modules: List[List[str]] = []
        for component in root.findall(schema + "Link"):
            # Only if a component ....
            if component.get("rel") == "component":
                swid = component.get("href")
                if not swid:
                    raise KeyError(f"Could not find href in {component}")
                swid = swid.replace("%20", " ")
                modules.append(self.extract(swid))

        return modules

    def extract(self, swid: str) -> List[str]:
        # Return parsed swid entry as [product, version] list item
        # Format of swid is "URI: <vendor>-<product>-<version>"
        item = swid[swid.find(":") + 1 :].split("-")
        # As some version numbers have leading 'v', it is removed
        return [item[1], item[2].upper().replace("V", "")]


if __name__ == "__main__":
    import sys

    parser = SWIDParser()
    file = sys.argv[1]
    print(parser.parse(file))
