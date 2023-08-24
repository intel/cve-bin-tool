.PHONY: all

SBOMS != ls *.spdx

all: $(SBOMS)
	$(foreach file, $(SBOMS), sbom2doc --input-file $(file) --format markdown --output-file "sboms_for_humans/$(basename $(file)).md"; echo "- [$(basename $(file))]($(basename $(file)).md)" >> sboms_for_humans/README.md;)
