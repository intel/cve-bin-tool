# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the PythonParser's handling of PKG-INFO files.
"""
import os
import shutil
import sys
import tempfile

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.pkg_info_pb2 as pkg_info_pb2
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER

with atheris.instrument_imports():
    from cve_bin_tool.parsers.python import PythonParser

cve_db = CVEDB()
logger = LOGGER.getChild("Fuzz")


def PkgInfoBuilder(data, file_path):
    """
    This function converts the given data into a PKG-INFO file.

    Args:
        data (protobuf message): The protobuf message to convert to a PKG-INFO file.
        file_path (str): The path to the file to write the PKG-INFO data to.
    """
    json_data = MessageToDict(
        data, preserving_proto_field_name=True, including_default_value_fields=True
    )

    with open(file_path, "w") as f:
        # Writing each field of PKG-INFO
        f.write(f"Metadata-Version: {json_data.get('metadata_version', '2.1')}\n")
        f.write(f"Name: {json_data.get('name', '')}\n")
        f.write(f"Version: {json_data.get('version', '')}\n")
        f.write(f"Summary: {json_data.get('summary', '')}\n")
        f.write(f"Home-page: {json_data.get('home_page', '')}\n")
        f.write(f"Author: {json_data.get('author', '')}\n")
        f.write(f"Author-email: {json_data.get('author_email', '')}\n")
        f.write(f"License: {json_data.get('license', '')}\n")

        # Writing keywords
        if "keywords" in json_data:
            f.write(f"Keywords: {', '.join(json_data['keywords'])}\n")

        # Writing classifiers
        for classifier in json_data.get("classifiers", []):
            f.write(f"Classifier: {classifier}\n")

        f.write(f"Requires-Python: {json_data.get('requires_python', '')}\n")
        f.write(f"License-File: {json_data.get('license_file', '')}\n")

        # Writing requires-dist
        for req_dist in json_data.get("requires_dist", []):
            f.write(f"Requires-Dist: {req_dist}\n")

        # Writing provides-extra
        for provides in json_data.get("provides_extra", []):
            f.write(f"Provides-Extra: {provides}\n")


def TestParseData(data, cve_db, logger, tmpdir):
    """
    Fuzz test the PythonParser's handling of PKG-INFO files.

    Args:
        data (protobuf message): The protobuf message to convert and process PKG-INFO files.
        cve_db: The CVE-Bin-tool Database object.
        logger: Logger object.
        tmpdir: Temporary Directory reference.
    """
    file_path = os.path.join(tmpdir, "PKG-INFO")
    try:
        PkgInfoBuilder(data)

        python_parser = PythonParser(cve_db, logger)
        python_parser.run_checker(file_path)

    except SystemExit:
        return


def main():
    """Main Function to Run Fuzzing and Facilitate Tempfile cleanup."""
    tmpdir = tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_PYTHON")
    try:
        atheris_libprotobuf_mutator.Setup(
            sys.argv,
            lambda data: TestParseData(data, cve_db, logger, tmpdir),
            proto=pkg_info_pb2.PkgInfo,
        )
        atheris.Fuzz()
    finally:
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
