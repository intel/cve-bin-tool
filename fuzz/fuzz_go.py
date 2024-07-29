# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
"""
This module contains fuzz testing for the GoParser's handling of go.mod files.
"""
import os
import shutil
import sys
import tempfile

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.go_mod_pb2 as go_mod_pb2
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER

with atheris.instrument_imports():
    from cve_bin_tool.parsers.go import GoParser

cve_db = CVEDB()
logger = LOGGER.getChild("Fuzz")


def GoModBuilder(data, file_path):
    """
    This function converts the given data into a go.mod file.

    Args:
        data (protobuf message): The protobuf message to convert to a go.mod file.
        file_path: The path of the file to build.
    """
    json_data = MessageToDict(
        data, preserving_proto_field_name=True, including_default_value_fields=True
    )

    with open(file_path, "w") as f:
        module_name = json_data.get("module_name", "")
        go_version = json_data.get("go_version", "")

        f.write(f"module {module_name}\n")
        f.write(f"go {go_version}\n")

        f.write("require (\n")
        for dependency in json_data.get("require", []):
            module_name = dependency.get("module_name", "")
            version = dependency.get("version", "")
            f.write(f"{module_name} {version}\n")
        f.write(")\n")

        f.write("replace (\n")
        for replacement in json_data.get("replace", []):
            old_module = replacement.get("old_module", "")
            old_version = replacement.get("old_version", "")
            new_module = replacement.get("new_module", "")
            new_version = replacement.get("new_version", "")
            f.write(f"{old_module} {old_version} => {new_module} {new_version}\n")
        f.write(")\n")

        f.write("exclude (\n")
        for exclusion in json_data.get("exclude", []):
            module_name = exclusion.get("module_name", "")
            version = exclusion.get("version", "")
            f.write(f"{module_name} {version}\n")
        f.write(")\n")


def TestParseData(data, cve_db, logger, tmpdir):
    """
    Fuzz testing function for the GoParser's handling of go.mod files.

    Args:
        data (protobuf message): The protobuf message to convert to a go.mod file.
        cve_db: The CVE-Bin-tool Database object.
        logger: Logger object.
        tmpdir: Temporary Directory reference.
    """
    file_path = os.path.join(tmpdir, "go.mod")
    try:
        GoModBuilder(data)

        go_parser = GoParser(cve_db, logger)
        go_parser.run_checker(file_path)

    except SystemExit:
        return


def main():
    """Main Function to Run Fuzzing and Facilitate Tempfile cleanup."""
    tmpdir = tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_GO")
    try:
        atheris_libprotobuf_mutator.Setup(
            sys.argv,
            lambda data: TestParseData(data, cve_db, logger, tmpdir),
            proto=go_mod_pb2.GoModFile,
        )
        atheris.Fuzz()
    finally:
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
