The cyclconedx_gen.xsd is an amalgamation of cyclonedx.xsd and cyclonedx_spdx.xsd. References
to spdx namespace in the cyclonedx.xsd is changed to bom.

The spdx.xsd has been generated from the test XML files as there is no official XSD schema.

The swid_gen.xsd has been generated from the test XML files as the official XSD schema (swid.xsd)
contains entities which are unsafe when parsed.

The pom.xsd file has been modified to ensure that all HTML tags have matching closure tags.

