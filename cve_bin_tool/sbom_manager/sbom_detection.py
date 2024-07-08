# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json

import defusedxml.ElementTree as ET

from cve_bin_tool.validator import validate_cyclonedx, validate_swid


def sbom_detection(file_path: str) -> str:
    """
    Identifies SBOM type of file based on its format and schema.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: The detected SBOM type (spdx, cyclonedx, swid) or None.
    """
    try:
        with open(file_path) as file:
            if ".spdx" in file_path:
                return "spdx"

            elif file_path.endswith(".json"):
                data = json.load(file)
                if (
                    "bomFormat" in data
                    and "specVersion" in data
                    and data["bomFormat"] == "CycloneDX"
                ):
                    return "cyclonedx"

                else:
                    return None

            elif file_path.endswith(".xml"):
                tree = ET.parse(file_path)
                root = tree.getroot()
                root_tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag
                if root_tag == "bom" and validate_cyclonedx(file_path):
                    return "cyclonedx"
                elif root_tag == "SoftwareIdentity" and validate_swid(file_path):
                    return "swid"
                else:
                    return None
            else:
                return None

    except (json.JSONDecodeError, ET.ParseError):
        return None
