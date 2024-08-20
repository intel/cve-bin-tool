from lib4sbom.parser import SBOMParser
from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
import os

os.environ['LIB4SBOM_CYCLONEDX_VERSION'] ="1.5"
test_parser = SBOMParser()
test_parser.parse_file("samples/cdx_1.6.json")
test_generator = SBOMGenerator(format="json", sbom_type="cyclonedx")
test_generator.generate("TestApp",test_parser.get_sbom())
sbom_output = SBOMOutput(filename="testapp.json", output_format="json")
sbom_output.generate_output(test_generator.get_sbom())