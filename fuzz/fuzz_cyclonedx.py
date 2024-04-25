# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the CycloneDXParser's handling of CycloneDX files.
"""

import json
import sys
import tempfile
from pathlib import Path

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.cyclonedx_pb2 as cyclonedx_pb2

with atheris.instrument_imports():
    from cve_bin_tool.sbom_manager import SBOMManager


def TestParseData(data):
    """
    This function converts the given data into a CycloneDX file.

    Args:
        data (protobuf message): The protobuf message to convert and process.
    """
    try:
        json_data = MessageToDict(
            data, preserving_proto_field_name=True, including_default_value_fields=True
        )

        components = []

        for dict in json_data.get("applications", []):
            dict["type"] = "application"
            components.append(dict)

        for dict in json_data.get("libraries", []):
            dict["type"] = "library"
            components.append(dict)

        del json_data["applications"]
        del json_data["libraries"]

        json_data["components"] = components

        with open(file_path, "w") as f:
            json.dump(json_data, f)

        sbom_engine = SBOMManager(file_path, sbom_type="cyclonedx")
        sbom_engine.scan_file()

    except SystemExit:
        return


file_path = str(
    Path(tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_CYCLONEDX"))
    / "test_intermediate.json"
)
atheris_libprotobuf_mutator.Setup(sys.argv, TestParseData, proto=cyclonedx_pb2.Cyclone)
atheris.Fuzz()
