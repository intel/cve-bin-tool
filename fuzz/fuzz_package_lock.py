# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the JavascriptParser's handling of package-lock.json files.
"""

import json
import sys
import tempfile
from pathlib import Path

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.package_lock_pb2 as package_lock_pb2
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER

with atheris.instrument_imports():
    from cve_bin_tool.parsers.javascript import JavascriptParser

cve_db = CVEDB()
logger = LOGGER.getChild("Fuzz")


def array_to_json(json_data):
    """Converts a list of json objects to a json object with the name as the key"""
    temp = {}
    for item in json_data:
        temp[item.pop("name")] = item

    return temp


def reformat_dependencies(dependencies):
    """
    reformats the 'requires' and 'dependencies' fields of each
    dependency in a list of dependencies.

    Args:
        dependencies (list): The list of dependencies to reformat.
    Returns:
        dict: The reformatted dependencies.
    """
    temp = {}
    for dep in dependencies:
        dep["requires"] = array_to_json(dep["requires"])
        if not dep["requires"]:
            dep.pop("requires")

        dep["dependencies"] = reformat_dependencies(dep["dependencies"])
        if not dep["dependencies"]:
            dep.pop("dependencies")

        temp[dep.pop("name")] = dep

    return temp


def TestParseData(data):
    """
    Fuzz testing function for the JavascriptParser's handling of package-lock.json files.

    Args:
        data (protobuf message): The protobuf message to convert to a dictionary and write to a file.
    """
    try:
        json_data = MessageToDict(
            data, preserving_proto_field_name=True, including_default_value_fields=True
        )

        with open(file_path, "w") as f:
            json_data["dependencies"] = reformat_dependencies(json_data["dependencies"])

            if not json_data["dependencies"]:
                json_data.pop("dependencies")

            f.write(json.dumps(json_data, indent=4))

        JP = JavascriptParser(cve_db, logger)
        JP.run_checker(file_path)

    except SystemExit:
        return


file_path = str(
    Path(tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_JAVASCRIPT")) / "package_lock.json"
)

atheris_libprotobuf_mutator.Setup(
    sys.argv, TestParseData, proto=package_lock_pb2.PackageLock
)
atheris.Fuzz()
