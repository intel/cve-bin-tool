# How do I use CVE Binary Tool to generate a SBOM?

The cve-bin-tool can be used to generate a software bill of materials (SBOM) file, which is a file that contains a list of all components detected by the scan in a standardized format.

## SBOM support

The cve-bin-tool generates SBOMs in the following formats

| SBOM Type | Format   | Filename extension |
| --------- | -------- | ------------------ |
| SPDX      | TagValue | .spdx              |
| SPDX      | JSON     | .spdx.json         |
| SPDX      | YAML     | .spdx.yaml         |
| SPDX      | YAML     | .spdx.yml          |
| CycloneDX | JSON     | .json              |

Details of the formats for each of the supported SBOM formats are available for [SPDX](https://spdx.dev/) and [CycloneDX](https://cyclonedx.org/)

## Usage

To generate a SBOM, run the tool as shown. See the examples below for details about optional arguments and default values used.

```
cve-bin-tool --sbom-type <sbom type> --sbom-format <sbom format> --sbom-output <sbom filename>
```

## Examples

Generate a SPDX SBOM in TagValue format with the name sbom.spdx

```
cve-bin-tool --sbom-type spdx --sbom-format tag --sbom-output sbom.spdx .
```

If the `--sbom-type` option is omitted, a SBOM is generated in the SPDX type. If the `--sbom-format` option is omitted, the format is inferred from the extension of the `--sbom-output` filename. The above and below examples are equivalent.

```
cve-bin-tool --sbom-output sbom.spdx
```

Generate a SPDX SBOM in YAML format with the name sbom.yml

```
cve-bin-tool --sbom-type spdx --sbom-format yaml --sbom-output sbom.yml
```

Generate a CycloneDX SBOM in JSON format with the name sbom.json. Note that CycloneDX SBOMs are only generated in JSON, so the `--sbom-format` option is unnecessary.

```
cve-bin-tool --sbom-type cyclonedx --sbom-output sbom.json
```
