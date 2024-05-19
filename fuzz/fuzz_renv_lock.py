# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the RParser's handling of renv.lock files.
"""

import os
import shutil
import sys
import tempfile

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.renv_lock_pb2 as renv_lock_pb2
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER

with atheris.instrument_imports():
    from cve_bin_tool.parsers.r import RParser


cve_db = CVEDB()
logger = LOGGER.getChild("Fuzz")


def RenvLockBuilder(data, file_path):
    """
    This function converts the given data into a renv.lock file.

    Args:
        data (protobuf message): The protobuf message to convert and process.
        file_path: The path of the file to build.
    """
    # Parse the JSON data
    json_data = MessageToDict(
        data, preserving_proto_field_name=True, including_default_value_fields=True
    )

    with open(file_path, "w") as f:
        # Write R version information
        r_version = json_data.get("r", {}).get("version", "")
        f.write("{\n")
        f.write('"R": {\n')
        if r_version:
            f.write(f'"Version": {r_version},\n')
        repositories = json_data.get("r", {}).get("repositories", {})
        f.write('"Repositories": [\n')
        for repository in repositories:
            name = repository.get("name", "")
            url = repository.get("url", "")
            f.write("{\n")
            f.write(f'"Name:{name},"')
            f.write(f'"URL":{url}')
            f.write("}\n")
        f.write("]\n")
        f.write("},\n")
        # Write Bioconductor version information
        bioconductor_version = json_data.get("bioconductor", []).get("version", "")
        f.write('"Bioconductor":{\n')
        if bioconductor_version:
            f.write(f"Version: {bioconductor_version}\n")
        f.write("},\n")
        f.write('"Packages":{\n')
        packages = json_data.get("packages", [])
        # Write packages
        for package in packages:
            name = package.get("package", "")
            f.write(f'"{name}": ')
            f.write("{\n")
            f.write(f'"Package:" {name},\n')
            version = package.get("version", "")
            f.write(f'"Version:" {version},\n')
            source = package.get("source", "")
            f.write(f'"Source:" {source},\n')
            repository = package.get("repository", "")
            f.write(f'"Repository:" {repository},\n')
            Hash = package.get("hash", "")
            f.write(f'"Hash:" {Hash}",\n')

            # Write requirements, if any
            requirements = package.get("requirements", [])
            if requirements:
                f.write("Requirements: [\n")
                for requirement in requirements:
                    f.write(f'"{requirement}",\n')
                f.write("]\n")
            f.write("}\n")
        f.write("}\n")


def TestParseData(data, cve_db, logger, tmpdir):
    """
    Fuzz test the RustParser's handling of renv.lock files.
    Args:
        data (protobuf message): The protobuf message to convert to a renv.lock file.
        cve_db: Object for the Database of CVE-BIN-TOOL.
        logger: Logger object.
        tmpdir: The temporary direct object.
    """
    file_path = os.path.join(tmpdir, "renv.lock")
    try:
        RenvLockBuilder(data, file_path)

        r_parser = RParser(cve_db, logger)
        r_parser.run_checker(file_path)

    except SystemExit:
        return


def main():
    """Main Function to Run Fuzzing and Facilitate Tempfile cleanup."""
    tmpdir = tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_R")
    try:
        atheris_libprotobuf_mutator.Setup(
            sys.argv,
            lambda data: TestParseData(data, cve_db, logger, tmpdir),
            proto=renv_lock_pb2.RenvLock,
        )
        atheris.Fuzz()
    finally:
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
