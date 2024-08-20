# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to show use of lib4sbom to convert an SPDX SBOM in tag value
### format to a SPDX SBOM in JSON format (and shown on console) and
### a CycloneDX file in JSON format (stored in a file)

from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.parser import SBOMParser

# Set up SBOM parser
test_parser = SBOMParser()
# Load SBOM - will autodetect SBOM type
test_parser.parse_file("test/data/test_sbom.spdx")
# test_parser.parse_file("test/data/spdx_test.spdx")

# Show relationships
# rel = test_parser.get_sbom()['relationships']
# for r in rel:
#     print(r)

# Set up SPDX-JSON generator
test_generator = SBOMGenerator(False, sbom_type="spdx", format="json")
# Generate sbom in JSON format to console (default)
test_generator.generate("TestApp", test_parser.get_sbom())

# # Set up SPDX-YAML generator
# test_generator2 = SBOMGenerator(False, sbom_type="spdx", format="yaml")
# # Generate sbom and store in a file
# test_generator2.generate("TestApp", test_parser.get_sbom(), filename="testapp2.spdx.yaml")
#
# Set up generator for CycloneDX
test_generator3 = SBOMGenerator(False, sbom_type="cyclonedx", format="json")
# Generate sbom in JSON format but don't send to console
test_generator3.generate("TestApp2", test_parser.get_sbom(), send_to_output=False)
# Get generated sbom
generated_output = test_generator3.get_sbom()
# And now available to do some processing e.g. put data in another format
# Send to file
# Method 1
test_generator3.generate("TestApp3", test_parser.get_sbom(), filename="testapp3.json")
# Method 2 - create a new output stream with already generated sbom data
# Send generated output to file testapp2.json
sbom_output = SBOMOutput(filename="testapp2.json", output_format="json")
sbom_output.generate_output(test_generator3.get_sbom())
#
# test_parser2 = SBOMParser()
# # Load YAML generated SBOM
# test_parser2.parse_file("testapp2.spdx.yaml")
# # ... regenerate tag value file
# test_generator4 = SBOMGenerator(False, sbom_type="spdx", format="tag")
# # And generate SBOM to file
# test_generator4.generate("TestApp", test_parser.get_sbom(), filename = "testapp2.spdx")
#
