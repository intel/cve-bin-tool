# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the PerlParser's handling of cpanfile files.
"""
import os
import shutil
import sys
import tempfile

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.cpanfile_pb2 as cpanfile_pb2
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER

with atheris.instrument_imports():
    from cve_bin_tool.parsers.perl import PerlParser

cve_db = CVEDB()
logger = LOGGER.getChild("Fuzz")


def cpanfileBuilder(data, file_path):
    """
    This function converts the given data into a cpanfile file.

    Args:
        data (protobuf message): The protobuf message to convert to a cpanfile file.
        file_path (str): The path to the file to write the cpanfile data to.
    """
    # Convert the Protobuf message to a dictionary
    json_data = MessageToDict(
        data, preserving_proto_field_name=True, including_default_value_fields=True
    )

    with open(file_path, "w") as f:
        # Writing general requirements
        for module in json_data.get("general_requirements", []):
            f.write(
                f'requires "{module.get("name", "")}" => "{module.get("version", "0")}";\n'
            )

        # Handling 'test' environment
        test_deps = json_data.get("test_dependencies", {})
        if test_deps:
            f.write("\non 'test' => sub {\n")
            for module in test_deps.get("test_requirements", []):
                f.write(
                    f'    requires "{module.get("name", "")}" => "{module.get("version", "0")}";\n'
                )
            for module in test_deps.get("test_recommends", []):
                f.write(
                    f'    recommends "{module.get("name", "")}" => "{module.get("version", "0")}";\n'
                )
            f.write("};\n")

        # Handling 'develop' environment
        develop_deps = json_data.get("develop_dependencies", {})
        if develop_deps:
            f.write("\non 'develop' => sub {\n")
            for module in develop_deps.get("develop_requirements", []):
                f.write(
                    f'    requires "{module.get("name", "")}" => "{module.get("version", "0")}";\n'
                )
            f.write("};\n")


def TestParseData(data, cve_db, logger, tmpdir):
    """
    Fuzz test the PerlParser's handling of cpanfile files.

    Args:
        data (protobuf message): The protobuf message to convert and process.
        cve_db: The CVE-Bin-tool Database object.
        logger: Logger object.
        tmpdir: Temporary Directory reference.
    """
    file_path = os.path.join(tmpdir, "cpanfile")
    try:
        cpanfileBuilder(data, file_path)

        perl_parser = PerlParser(cve_db, logger)
        perl_parser.run_checker(file_path)

    except SystemExit:
        return


def main():
    """Main Function to Run Fuzzing and Facilitate Tempfile cleanup."""
    tmpdir = tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_PERL")
    try:
        atheris_libprotobuf_mutator.Setup(
            sys.argv,
            lambda data: TestParseData(data, cve_db, logger, tmpdir),
            proto=cpanfile_pb2.CPANFile,
        )
        atheris.Fuzz()
    finally:
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
