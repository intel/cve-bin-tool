# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the PackageListParser's handling of package lists.
"""

import sys
import tempfile
from pathlib import Path

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.packages_pb2 as packages_pb2

with atheris.instrument_imports():
    import cve_bin_tool.package_list_parser as PLP


def TestListParser(file_name: str, text: str):
    """
    Test the PackageListParser for the given file and text.

    Args:
        file_name (str): The name of the file to write the text to.
        text (str): The text to write to the file.
    """
    try:
        with open(file_name, "w") as f:
            f.writelines(text)
        list_parser = PLP.PackageListParser(file_name)
        list_parser.parse_list()

    except SystemExit:
        # force return on SystemExit since those are mostly InsufficientArgs
        return
    except UnicodeEncodeError:
        pass


def TestPackageData(data):
    """
    Fuzz Test the PackageListParser with the given protobuf message.

    Args:
        data (protobuf message): The protobuf message to convert and process.
    """
    with_version = []
    without_version = []
    json_data = MessageToDict(
        data, preserving_proto_field_name=True, including_default_value_fields=True
    )

    print(json_data)

    for dict in json_data.get("packages", []):
        if "version" in dict:
            with_version.append(dict.get("name") + "==" + str(abs(dict.get("version"))))
        else:
            without_version.append(dict.get("name"))

    TestListParser(str(tempdir / "test.txt"), without_version)

    TestListParser(str(tempdir / "test_requirements.txt"), with_version)


tempdir = Path(tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_PACKAGE_LIST"))
atheris_libprotobuf_mutator.Setup(
    sys.argv, TestPackageData, proto=packages_pb2.PackageList
)
atheris.Fuzz()
