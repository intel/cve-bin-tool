# How do I use CVE Binary Tool to generate a VEX?

The cve-bin-tool can be used to generate a Vulnerability Exploitability eXchange (VEX) file, which is a file that contains a list of all vulnerabilities detected by the scan in a standardized format.

## VEX support

The cve-bin-tool generates VEXs in the following formats

| SBOM Type | Format   | Filename extension |
| --------- | -------- | ------------------ |
| CycloneDX | JSON     | .json              |
| CSAF      | JSON     | .json              |
| OpenVEX   | JSON     | .json              |


Details of the formats for each of the supported VEX formats are available for [CSAF](https://oasis-open.github.io/csaf-documentation/), [CycloneDX](https://cyclonedx.org/capabilities/vex/) and [OpenVEX](https://edu.chainguard.dev/open-source/sbom/what-is-openvex/)

## Usage

To generate a VEX, run the tool as shown. See the examples below for details about optional arguments and default values used.

```
cve-bin-tool --vex-type <vex type> --vex-output <vex filename>
```

## Examples

Generate a CSAF vex with the name samplevex.json

```
cve-bin-tool --vex-type csaf --sbom-output samplevex.json .
```

If the `--vex-type` option is omitted, a VEX is generated in the CycloneDX type. --vex-output is used for providing a filename for output vex file.

```
cve-bin-tool --vex-output samplevex.json
```

Generate a OpenVEX vex with the name samplevex.json

```
cve-bin-tool --vex-type openvex --vex-output samplevex.json
```
