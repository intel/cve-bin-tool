from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.parser import SBOMParser

tp = SBOMParser()
tp.parse_file("/tmp/system.json")
print(tp.get_sbom())
tg = SBOMGenerator(False, sbom_type="spdx", format="tag")
tg.generate("Systen_App", tp.get_sbom())
so = SBOMOutput(filename="/tmp/system1.spdx", output_format="tag")
so.generate_output(tg.get_sbom())
