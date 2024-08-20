# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to convert an SPDX SBOM in tag value
### format to a SPDX SBOM in JSON format (and shown on console) and
### a CycloneDX file in JSON format (stored in a file)

import sys

from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.parser import SBOMParser

# Set up SBOM parser
test_parser = SBOMParser()
# Load SBOM - will autodetect SBOM type
test_parser.parse_file(sys.argv[1])

# for p in test_parser.get_packages():
#     print (p['name'], p['licensedeclared'], p['version'], p['id'])


# print (test_parser.get_sbom())
# Set up SPDX-JSON generator
test_generator = SBOMGenerator(False, sbom_type="spdx", format="tag")
# Generate sbom in JSON format to console (default)
test_generator.generate("TestApp", test_parser.get_sbom(), send_to_output=False)
sbom_output = SBOMOutput(filename=sys.argv[2], output_format="tag")
sbom_output.generate_output(test_generator.get_sbom())
