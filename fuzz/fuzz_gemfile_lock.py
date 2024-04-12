# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the RubyParser's handling of Gemfile.lock files.
"""

import os
import shutil
import sys
import tempfile

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.gemfile_lock_pb2 as gemfile_lock_pb2
from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER

with atheris.instrument_imports():
    from cve_bin_tool.parsers.ruby import RubyParser

cve_db = CVEDB()
logger = LOGGER.getChild("Fuzz")


def GemfileLockBuilder(data, file_path):
    """
    This function converts the given data into a Gemfile.lock file.
    Args:
        data (protobuf message): The protobuf message to convert to a Gemfile.lock file.
        file_path: File path of the file to write the Gemfile.lock into.
    """
    json_data = MessageToDict(
        data, preserving_proto_field_name=True, including_default_value_fields=True
    )

    with open(file_path, "w") as f:
        for git_pkg in json_data.get("git_packages", []):
            f.write("GIT\n")
            f.write(f'  remote: {git_pkg.get("remote", "")}\n')
            f.write(f'  revision: {git_pkg.get("revision", "")}\n')
            if git_pkg.get("branch"):
                f.write(f'  branch: {git_pkg.get("branch", "")}\n')
            f.write("  specs:\n")
            for spec in git_pkg.get("specs", []):
                f.write(f'    {spec.get("name", "")} ({spec.get("version", "")})\n')
                for dep in spec.get("dependencies", []):
                    f.write(f"      {dep}\n")

        # Handling PATH packages
        for path_pkg in json_data.get("path_packages", []):
            f.write("PATH\n")
            f.write(f'  remote: {path_pkg.get("remote", "")}\n')
            f.write("  specs:\n")
            for spec in path_pkg.get("specs", []):
                f.write(f'    {spec.get("name", "")} ({spec.get("version", "")})\n')
                for dep in spec.get("dependencies", []):
                    f.write(f"      {dep}\n")

        # Handling GEM packages
        for gem_pkg in json_data.get("gem_packages", []):
            f.write("GEM\n")
            f.write(f'  remote: {gem_pkg.get("remote", "")}\n')
            f.write("  specs:\n")
            for spec in gem_pkg.get("specs", []):
                f.write(f'    {spec.get("name", "")} ({spec.get("version", "")})\n')
                for dep in spec.get("dependencies", []):
                    f.write(f"      {dep}\n")

        # Handling platforms
        f.write("PLATFORMS\n")
        for platform in json_data.get("platforms", []):
            f.write(f"  {platform}\n")

        # Handling dependencies
        f.write("DEPENDENCIES\n")
        for dep in json_data.get("dependencies", []):
            f.write(f"  {dep}\n")

        # Handling bundled with
        bundled_with = json_data.get("bundled_with", "")
        if bundled_with:
            f.write(f"BUNDLED WITH\n   {bundled_with}\n")


def TestParseData(data, cve_db, logger, tmpdir):
    """
    Fuzz test the RustParser's handling of Gemfile.lock files.
    Args:
        data (protobuf message): The protobuf message to convert to a Gemfile.lock file.
        cve_db: Object for the Database of CVE-BIN-TOOL.
        logger: Logger object.
        tmpdir: The temporary direct object.
    """
    file_path = os.path.join(tmpdir, "Gemfile.lock")
    try:
        GemfileLockBuilder(data)

        ruby_parser = RubyParser(cve_db, logger)
        ruby_parser.run_checker(file_path)

    except SystemExit:
        return


def main():
    tmpdir = tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_RUBY")

    try:
        atheris_libprotobuf_mutator.Setup(
            sys.argv,
            lambda data: TestParseData(data, cve_db, logger, tmpdir),
            proto=gemfile_lock_pb2.GemfileLock,
        )
        atheris.Fuzz()
    finally:
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
