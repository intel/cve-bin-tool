# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module contains fuzz testing for the JavaParser's handling of pom.xml files.
"""
import os
import shutil
import sys
import tempfile

import atheris
import atheris_libprotobuf_mutator
import generated.pom_xml_pb2 as pom_xml_pb2
from google.protobuf.json_format import MessageToDict

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.log import LOGGER

with atheris.instrument_imports():
    from cve_bin_tool.parsers.java import JavaParser

cve_db = CVEDB()
logger = LOGGER.getChild("Fuzz")


def PomXmlBuilder(data, file_path):
    """
    This function converts the given data into a pom.xml file.

    Args:
        data (protobuf message): The protobuf message to convert and process.
        file_path: The path of the file to build.
    """
    json_data = MessageToDict(
        data, preserving_proto_field_name=True, including_default_value_fields=True
    )

    with open(file_path, "w") as f:
        xml_namespace = json_data.get("xml_namespace", "")
        xml_schema_instance = json_data.get("xml_schema_instance", "")
        xml_namespace_uri1 = json_data.get("xml_namespace_uri1", "")
        xml_namespace_uri2 = json_data.get("xml_namespace_uri2", "")
        model_version = json_data.get("model_version", "")
        packaging = json_data.get("packaging", "")
        group_id = json_data.get("group_Id", "")
        artifactid = json_data.get("artifactId", "")
        name = json_data.get("name", "")
        url = json_data.get("url", "")
        version = json_data.get("version", "")

        f.write(f'<project xmlns="{xml_namespace}"\n')
        f.write(f'xmlns:xsi="{xml_schema_instance}"\n')
        f.write(f'xsi:schemaLocation="{xml_namespace_uri1} {xml_namespace_uri2}">\n')
        f.write(f"<modelVersion>{model_version}</modelVersion>\n")
        f.write(f"<groupId>{group_id}</groupId>\n")
        f.write(f"<artifactId>{artifactid}</artifactId>\n")
        f.write(f"<version>{version}</version>\n")
        f.write(f"<packaging>{packaging}</packaging>\n")
        f.write(f"<name>{name}</name>\n")
        f.write(f"<url>{url}</url>\n")

        f.write("<dependencies>\n")
        dependencies = json_data.get("dependencies", [])
        for dependency in dependencies:
            f.write("<dependency>\n")
            group_id = dependency.get("group_Id", "")
            artifactid = dependency.get("artifactId", "")
            version = dependency.get("version", "")
            scope = dependency.get("scope", "")
            f.write(f"<groupId>{group_id}</groupId>\n")
            f.write(f"<artifactId>{artifactid}</artifactId>\n")
            f.write(f"<version>{version}</version>\n")
            f.write(f"<scope>{scope}</scope>\n")
            f.write("</dependency>\n")
        f.write("</dependencies>\n")

        f.write("<build>\n")
        f.write("<plugins>\n")
        plugins = json_data.get("plugins", [])
        for plugin in plugins:
            f.write("<plugin>\n")
            group_id = plugin.get("group_Id", "")
            artifactid = plugin.get("artifactId", "")
            version = plugin.get("version", "")
            f.write(f"<groupId>{group_id}</groupId>\n")
            f.write(f"<artifactId>{artifactid}</artifactId>\n")
            f.write(f"<version>{version}</version>\n")
            f.write("</plugin>\n")
        f.write("</build>\n")
        f.write("</plugins>\n")

        f.write("</project>\n")


def TestParseData(data, cve_db, logger, tmpdir):
    """
    Fuzz testing function for the JavaParser's handling of pom.xml files.

    Args:
        data (protobuf message): The protobuf message to convert and process.
        cve_db: The CVE-Bin-tool Database object.
        logger: Logger object.
        tmpdir: Temporary Directory reference.
    """
    file_path = os.path.join(tmpdir, "pom.xml")
    try:
        PomXmlBuilder(data)

        java_parser = JavaParser(cve_db, logger)
        java_parser.run_checker(file_path)

    except SystemExit:
        return


def main():
    """Main Function to Run Fuzzing and Facilitate Tempfile cleanup."""
    tmpdir = tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_JAVA")
    try:
        atheris_libprotobuf_mutator.Setup(
            sys.argv,
            lambda data: TestParseData(data, cve_db, logger, tmpdir),
            proto=pom_xml_pb2.PomXmlProject,
        )
        atheris.Fuzz()
    finally:
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
