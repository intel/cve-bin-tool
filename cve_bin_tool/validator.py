# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

import xmlschema

from cve_bin_tool.log import LOGGER


def _validate_xml(filename, xsd_file):

    # Resolve folder where schemas are present
    schemas_file = Path(__file__).resolve().parent / "schemas" / xsd_file
    the_schema = xmlschema.XMLSchema(Path(schemas_file))

    LOGGER.debug(f"Validate {filename} against the_schema in {schemas_file}")
    try:
        result = the_schema.validate(filename)
    except Exception as e:
        LOGGER.debug(f"Failed to validate {filename} against {xsd_file}. Exception {e}")
        result = "Fail"
    return result is None


def validate_spdx(filename):
    SPDX_SCHEMA = "spdx.xsd"
    return _validate_xml(filename, SPDX_SCHEMA)


def validate_cyclonedx(filename):
    CYCLONEDX_SCHEMA = "cyclonedx_gen.xsd"
    return _validate_xml(filename, CYCLONEDX_SCHEMA)


def validate_swid(filename):
    SWID_SCHEMA = "swid_gen.xsd"
    return _validate_xml(filename, SWID_SCHEMA)


def validate_pom(filename):
    POM_SCHEMA = "pom.xsd"
    return _validate_xml(filename, POM_SCHEMA)
