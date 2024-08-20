# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to convert an SPDX SBOM in tag value
### format to a SPDX SBOM in JSON format (and shown on console) and
### a CycloneDX file in JSON format (stored in a file)

from lib4sbom.parser import SBOMParser
from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput

# Set up SBOM parser
test_parser = SBOMParser()
# Load SBOM - will autodetect SBOM type
test_parser.parse_file("test/data/test2_sbom.spdx")
#test_parser.parse_file("test/data/spdx_test.spdx")

# Show relationships
# rel = test_parser.get_sbom()['relationships']
# for r in rel:
#     print(r)

# print (test_parser.get_sbom())
# Show packages
# pack = [x for x in test_parser.get_sbom()['packages'].values()]
# for p in pack:
#     print(p)

# Set up SPDX-JSON generator
test_generator = SBOMGenerator(False, sbom_type="cyclonedx", format="json")
# Generate sbom in JSON format to console (default)
test_generator.generate("TestApp", test_parser.get_sbom())

