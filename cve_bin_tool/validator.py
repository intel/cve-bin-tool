# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later
import logging
from pathlib import Path

from cve_bin_tool.log import LOGGER

# This downgrades a message during module loading.
if True:  # Strange construction for pep8 compliance.
    logging.getLogger("xmlschema").setLevel(logging.WARNING)
    import xmlschema


def _validate_xml(filename, xsd_file):
    """
    Validates an XML file against a specified XSD schema.

    The XSD schema file contains the 'grammar rules' that the XML file should follow.
    It first constructs the path to the XSD schema file, then it creates an XMLSchema object using the xmlschema library.
    It logs a debug message about the validation process, then attempts to validate the XML file against the schema.
    If the XML file doesn't follow the rules, the function will log a message about what went wrong and return False.
    If the XML file does follow the rules, the function will return True.


    Args:
        filename (str): The path to the XML file to validate.
        xsd_file (str): The name of the XSD schema file to validate against.

    Returns:
        bool: True if the XML file is valid according to the schema, False otherwise.
    """
    # Resolve the folder where schemas are located.
    schemas_file = Path(__file__).resolve().parent / "schemas" / xsd_file
    the_schema = xmlschema.XMLSchema(Path(schemas_file))

    LOGGER.debug(f"Validating {filename} against the schema in {schemas_file}")
    try:
        result = the_schema.validate(filename)
    except Exception as e:
        LOGGER.debug(f"Failed to validate {filename} against {xsd_file}. Exception {e}")
        result = False
    return result is None


def validate_spdx(filename):
    """
    This function validates an SPDX file against the SPDX schema.
    SPDX is a SBOM standard developed by the Linux Foundation. It is an XML or JSON schema that
    describes the strcuture of an SPDX document.

    Args:
        filename (str): The path to the SPDX file to validate.

    Returns:
        bool: True if the SPDX file is valid according to the schema, False otherwise.
    """
    SPDX_SCHEMA = "spdx.xsd"
    return _validate_xml(filename, SPDX_SCHEMA)


def validate_cyclonedx(filename):
    """
    This function validates a CycloneDX file against the CycloneDX schema. It is an XML or JSON schema that
    defines the structure of CycloneDX SBOM.

    Args:
        filename (str): The path to the CycloneDX file to validate.

    Returns:
        bool: True if the CycloneDX file is valid according to the schema, False otherwise.
    """
    CYCLONEDX_SCHEMA = "cyclonedx_gen.xsd"
    return _validate_xml(filename, CYCLONEDX_SCHEMA)


def validate_swid(filename):
    """
    This function validates a SWID (Software Identification Tag) file against the SWID schema.
    It is an XML or JSON schema that defines the structure of SWID tags.
    An SWID tag is an XML document that provides information about a specific software product,
    including its name, version, and publisher. It can also include other details like
    the software's license and the files that are installed with the software.

    Args:
        filename (str): The path to the SWID file to validate.

    Returns:
        bool: True if the SWID file is valid according to the schema, False otherwise.
    """
    SWID_SCHEMA = "swid_gen.xsd"
    return _validate_xml(filename, SWID_SCHEMA)


def validate_pom(filename):
    """
    This function checks for the validation of an POM (Project Object Model) file against the POM schema.
    A POM file is an XML file that contains information about the project and configuration
    details used by Maven to build the project.

    Args:
        filename (str): The path to the POM file to validate.

    Returns:
        bool: True if the POM file is valid according to the schema, False otherwise.
    """
    POM_SCHEMA = "pom.xsd"
    return _validate_xml(filename, POM_SCHEMA)
