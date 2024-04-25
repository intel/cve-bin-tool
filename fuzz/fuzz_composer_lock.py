# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the PhpParser's handling of composer.lock files.
"""

import json
import os
import shutil
import sys
import tempfile

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.composer_lock_pb2 as composer_lock_pb2
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER

with atheris.instrument_imports():
    from cve_bin_tool.parsers.php import PhpParser

cve_db = CVEDB()
logger = LOGGER.getChild("Fuzz")


def ComposerLockBuilder(data, file_path):
    """
    This function converts the given data into a composer.lock file.

    Args:
        data (protobuf message): The protobuf message to convert to a composer.lock file.
        file_path: The path of the file to build.
    """
    json_data = MessageToDict(
        data, preserving_proto_field_name=True, including_default_value_fields=True
    )

    with open(file_path, "w") as f:
        f.write("{\n")

        # Adding _readme
        f.write('    "_readme": [\n')
        for line in json_data.get("_readme", []):
            f.write(f'        "{line}",\n')
        f.write("    ],\n")

        # Adding content-hash
        f.write(f'    "content-hash": "{json_data.get("content_hash", "")}",\n')

        # Adding packages
        f.write('    "packages": [\n')
        for package in json_data.get("packages", []):
            f.write("        {\n")
            f.write(f'            "name": "{package.get("name", "")}",\n')
            f.write(f'            "version": "{package.get("version", "")}",\n')
            # Add other fields for each package...
            f.write("        },\n")
        f.write("    ],\n")

        # Adding packages-dev
        f.write('    "packages-dev": [\n')
        for package_dev in json_data.get("packages_dev", []):
            f.write("        {\n")
            f.write(f'            "name": "{package_dev.get("name", "")}",\n')
            f.write(f'            "version": "{package_dev.get("version", "")}",\n')
            # Add other fields for each package-dev...
            f.write("        },\n")
        f.write("    ],\n")

        # Adding aliases
        f.write('    "aliases": [\n')
        for alias in json_data.get("aliases", []):
            f.write(f'        "{alias}",\n')
        f.write("    ],\n")

        # Adding other top-level fields
        f.write(
            f'    "minimum-stability": "{json_data.get("minimum_stability", "stable")}",\n'
        )
        f.write(
            f'    "stability-flags": {json.dumps(json_data.get("stability_flags", []))},\n'
        )
        f.write(
            f'    "prefer-stable": {str(json_data.get("prefer_stable", False)).lower()},\n'
        )
        f.write(
            f'    "prefer-lowest": {str(json_data.get("prefer_lowest", False)).lower()},\n'
        )

        # Platform and Platform-dev
        f.write('    "platform": {\n')
        for key, value in json_data.get("platform", {}).items():
            f.write(f'        "{key}": "{value}",\n')
        f.write("    },\n")

        f.write('    "platform-dev": {\n')
        for key, value in json_data.get("platform_dev", {}).items():
            f.write(f'        "{key}": "{value}",\n')
        f.write("    },\n")

        # Plugin-api-version
        f.write(
            f'    "plugin-api-version": "{json_data.get("plugin_api_version", "")}"\n'
        )

        f.write("}\n")


def TestParseData(data, cve_db, logger, tmpdir):
    """
    Fuzz testing function for the PhpParser's handling of composer.lock files.

    Args:
        data (protobuf message): The protobuf message to convert to a composer.lock file.
        cve_db: The CVE-Bin-tool Database object.
        logger: Logger object.
        tmpdir: Temporary Directory reference.
    """
    file_path = os.path.join(tmpdir, "composer.lock")
    try:
        ComposerLockBuilder(data)

        php_parser = PhpParser(cve_db, logger)
        php_parser.run_checker(file_path)

    except SystemExit:
        return


def main():
    """Main Function to Run Fuzzing and Facilitate Tempfile cleanup."""
    tmpdir = tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_PHP")
    try:
        atheris_libprotobuf_mutator.Setup(
            sys.argv,
            lambda data: TestParseData(data, cve_db, logger, tmpdir),
            proto=composer_lock_pb2.ComposerLock,
        )
        atheris.Fuzz()
    finally:
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
