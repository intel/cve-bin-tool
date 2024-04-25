# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
import tempfile
from pathlib import Path

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.package_resolved_pb2 as package_resolved_pb2
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER

with atheris.instrument_imports():
    from cve_bin_tool.parsers.swift import SwiftParser

cve_db = CVEDB()
logger = LOGGER.getChild("Fuzz")


def PackageResolvedBuilder(data):
    """Convert the Protobuf message to a dictionary"""
    json_data = MessageToDict(
        data, preserving_proto_field_name=True, including_default_value_fields=True
    )

    with open(file_path, "w") as f:
        f.write("{\n")
        f.write('  "object": {\n')
        f.write('    "pins": [\n')

        # Iterating through package pins
        for i, pin in enumerate(json_data.get("object", {}).get("pins", [])):
            f.write("      {\n")
            f.write(f'        "package": "{pin.get("package", "")}",\n')
            f.write(f'        "repositoryURL": "{pin.get("repositoryURL", "")}",\n')
            f.write('        "state": {\n')
            state = pin.get("state", {})
            f.write(f'          "branch": {json.dumps(state.get("branch"))},\n')
            f.write(f'          "revision": "{state.get("revision", "")}",\n')
            f.write(f'          "version": "{state.get("version", "")}"\n')
            f.write("        }\n")
            f.write(
                "      }"
                + (
                    ","
                    if i < len(json_data.get("object", {}).get("pins", [])) - 1
                    else ""
                )
                + "\n"
            )

        f.write("    ]\n")
        f.write("  },\n")
        f.write(f'  "version": {json_data.get("version", 1)}\n')
        f.write("}\n")


def TestParseData(data):
    try:
        PackageResolvedBuilder(data)

        swift_parser = SwiftParser(cve_db, logger)
        swift_parser.run_checker(file_path)

    except SystemExit:
        return


file_path = str(
    Path(tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_PACKAGE_RESOLVED"))
    / "Package.resolved"
)

atheris_libprotobuf_mutator.Setup(
    sys.argv, TestParseData, proto=package_resolved_pb2.PackageResolved
)
atheris.Fuzz()
