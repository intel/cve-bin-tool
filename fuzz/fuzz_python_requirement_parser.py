# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the PythonRequirementsParser handling of requirements.txt files.
"""

import os
import shutil
import sys
import tempfile

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.python_requirements_pb2 as python_requirements_pb2
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER

with atheris.instrument_imports():
    from cve_bin_tool.parsers.python import PythonRequirementsParser

cve_db = CVEDB()
logger = LOGGER.getChild("Fuzz")


def TestParseData(data, cve_db, logger, tmpdir):
    """
    Fuzz test the PythonRequirementsParser handling of requirements.txt files.
    Args:
        data (protobuf message): The protobuf message to convert to a requirements.txt file.
        cve_db: Object for the Database of CVE-BIN-TOOL.
        logger: Logger object.
        tmpdir: The temporary directory object.
    """
    try:
        json_data = MessageToDict(
            data, preserving_proto_field_name=True, including_default_value_fields=True
        )
        file_path = os.path.join(tmpdir, "requirements.txt")
        with open(file_path, "w") as f:
            for dict in json_data.get("packages", []):
                extras = ""
                if len(dict["extras"]) > 0:
                    extras = f"[{','.join(dict['extras'])}]"

                constraint = ""
                if "version" in dict.keys():
                    constraint = f" == {dict['version']}"
                elif "url" in dict.keys():
                    constraint = f"@{dict['url']}"

                f.write(f"{dict['name']}{extras}{constraint}\n")

        PRP = PythonRequirementsParser(cve_db, logger)
        PRP.run_checker(file_path)

    except SystemExit:
        return


def main():
    """Main Function to Run Fuzzing and Facilitate Tempfile cleanup."""
    tmpdir = tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_PYTHON_REQUIREMENTS")
    try:
        atheris_libprotobuf_mutator.Setup(
            sys.argv,
            lambda data: TestParseData(data, cve_db, logger, tmpdir),
            proto=python_requirements_pb2.PackageList,
        )
        atheris.Fuzz()
    finally:
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
