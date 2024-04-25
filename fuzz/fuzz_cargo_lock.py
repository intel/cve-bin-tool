# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the RustParser's handling of Cargo.lock files.
"""

import os
import shutil
import sys
import tempfile

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.cargo_lock_pb2 as cargo_lock_pb2
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER

with atheris.instrument_imports():
    from cve_bin_tool.parsers.rust import RustParser

cve_db = CVEDB()
logger = LOGGER.getChild("Fuzz")


def CargoLockBuilder(data, file_path):
    """
    This function converts the given data into a Cargo.lock file.

    Args:
        data (protobuf message): The protobuf message to convert to a Cargo.lock file.
    """
    json_data = MessageToDict(
        data, preserving_proto_field_name=True, including_default_value_fields=True
    )

    with open(file_path, "w") as f:
        for package_data in json_data.get("packages", []):
            package_name = package_data.get("name", "")
            package_version = package_data.get("version", "")
            f.write("[[package]]\n")
            f.write(f'name = "{package_name}"\n')
            f.write(f'version = "{package_version}"\n')
            package_source = package_data.get("source", "")
            if package_source != "":
                f.write(f'source = "{package_source}"\n')
            package_checksum = package_data.get("checksum", "")
            if package_checksum != "":
                f.write(f'checksum = "{package_checksum}"\n')

            dependencies = package_data.get("dependency", [])
            f.write("dependencies = [\n")
            for dependency in dependencies:
                name = dependency.get("name", "")
                version = dependency.get("version", "")
                url = dependency.get("url", "")
                f.write(f' "{name}')
                if version != "":
                    f.write(f" {version}")
                if url != "":
                    f.write(f" {url}")
                f.write('",\n')
            f.write("]\n")
            f.write("\n")


def TestParseData(data, cve_db, logger, tmpdir):
    """
    Fuzz test the RustParser's handling of Cargo.lock files.

    Args:
        data (protobuf message): The protobuf message to convert to a Cargo.lock file.
    """
    file_path = os.path.join(tmpdir, "Cargo.lock")
    try:
        CargoLockBuilder(data, file_path)

        rust_parser = RustParser(cve_db, logger)
        rust_parser.run_checker(file_path)

    except SystemExit:
        return


def main():
    tmpdir = tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_RUST")
    try:
        atheris_libprotobuf_mutator.Setup(
            sys.argv,
            lambda data: TestParseData(data, cve_db, logger, tmpdir),
            proto=cargo_lock_pb2.CargoLock,
        )
        atheris.Fuzz()
    finally:
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
