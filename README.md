# CVE Binary Tool quick start / README

[![Build Status](https://github.com/intel/cve-bin-tool/workflows/cve-bin-tool/badge.svg?branch=main&event=push)](https://github.com/intel/cve-bin-tool/actions)
[![codecov](https://codecov.io/gh/intel/cve-bin-tool/branch/main/graph/badge.svg)](https://codecov.io/gh/intel/cve-bin-tool)
[![Gitter](https://badges.gitter.im/cve-bin-tool/community.svg)](https://gitter.im/cve-bin-tool/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![On ReadTheDocs](https://readthedocs.org/projects/cve-bin-tool/badge/?version=latest&style=flat)](https://cve-bin-tool.readthedocs.io/en/latest/)
[![On PyPI](https://img.shields.io/pypi/v/cve-bin-tool)](https://pypi.org/project/cve-bin-tool/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5380/badge)](https://bestpractices.coreinfrastructure.org/projects/5380)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/intel/cve-bin-tool/badge)](https://api.securityscorecards.dev/projects/github.com/intel/cve-bin-tool)

The CVE Binary Tool is a free, open source tool to help you find known vulnerabilities in software, using data from the [National Vulnerability Database](https://nvd.nist.gov/) (NVD) list of [Common Vulnerabilities and Exposures](<https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures#:~:text=Common%20Vulnerabilities%20and%20Exposures%20(CVE)%20is%20a%20dictionary%20of%20common,publicly%20known%20information%20security%20vulnerabilities.>) (CVEs).

The tool has two main modes of operation:

1. A binary scanner which helps you determine which packages may have been included as part of a piece of software. There are <!-- NUMBER OF CHECKERS START-->290<!--NUMBER OF CHECKERS END--> checkers which focus on common, vulnerable open source components such as openssl, libpng, libxml2 and expat.
2. Tools for scanning known component lists in various formats, including .csv, several linux distribution package lists, language specific package scanners and several Software Bill of Materials (SBOM) formats.

It is intended to be used as part of your continuous integration system to enable regular vulnerability scanning and give you early warning of known issues in your supply chain.

What CVE Binary Tool does when it runs:

![Diagram of cve-bin-tool's workflow, described in text with more detail below.](https://raw.githubusercontent.com/intel/cve-bin-tool/main/doc/images/cve-bin-tool-workflow-800px.png)

1. Download CVE Data (from NVD, Redhat, OSV, Gitlab, and Curl).
    - This happens once per day by default, not every time a scan is run.
    - On first run, downloading all data can take some time.
2. Create/read a component list.  There are two modes of operation:
    1. Creates a component list (including versions) using a combination of binary checkers and language component lists (such as python's requirements.txt).
    2. Read SBOM (use an existing component list in a standardized Software Bill of Materials format.)
3. Create CVE List
    - This looks up all components found or read from an existing bill of materials and reports back any known issues associated with them
4. Include triage/additional data
    - There are several options for adding triage/notes, information from previous reports to track vulnerability change over time, or known fix data
5. Generate report in one or more formats (console, json, csv, html, pdf)

For more details, see our [documentation](https://cve-bin-tool.readthedocs.io/en/latest/) or this [quickstart guide](https://cve-bin-tool.readthedocs.io/en/latest/README.html)

- [CVE Binary Tool quick start / README](#cve-binary-tool-quick-start--readme)
  - [Installing CVE Binary Tool](#installing-cve-binary-tool)
  - [Setting up an NVD\_API\_KEY](#setting-up-an-nvd_api_key)
  - [Most popular usage options](#most-popular-usage-options)
    - [Finding known vulnerabilities using the binary scanner](#finding-known-vulnerabilities-using-the-binary-scanner)
    - [Finding known vulnerabilities in a list of components](#finding-known-vulnerabilities-in-a-list-of-components)
    - [Scanning an SBOM file for known vulnerabilities](#scanning-an-sbom-file-for-known-vulnerabilities)
    - [Providing triage input](#providing-triage-input)
    - [Using the tool offline](#using-the-tool-offline)
  - [Output Options](#output-options)
  - [Full option list](#full-option-list)
  - [Configuration](#configuration)
  - [Using CVE Binary Tool in GitHub Actions](#using-cve-binary-tool-in-github-actions)
  - [Data Sources](#data-sources)
    - [National Vulnerability Database (NVD)](#national-vulnerability-database-nvd)
    - [Open Source Vulnerability Database (OSV)](#open-source-vulnerability-database-osv)
    - [Gitlab Advisory Database (GAD)](#gitlab-advisory-database-gad)
    - [RedHat Security Database (REDHAT)](#redhat-security-database-redhat)
    - [Curl Database (Curl)](#curl-database-curl)
  - [Binary checker list](#binary-checker-list)
  - [Language Specific checkers](#language-specific-checkers)
    - [Java](#java)
    - [Javascript](#javascript)
    - [Rust](#rust)
    - [Ruby](#ruby)
    - [R](#r)
    - [Go](#go)
    - [Swift](#swift)
    - [Python](#python)
    - [Perl](#perl)
  - [SBOM Generation](#sbom-generation)
  - [Limitations](#limitations)
  - [Additional Requirements](#additional-requirements)
  - [Supported Archive Formats](#supported-archive-formats)
  - [Feedback \& Contributions](#feedback--contributions)
  - [Security Issues](#security-issues)

## Installing CVE Binary Tool

CVE Binary Tool can be installed using pip:

```console
pip install cve-bin-tool
```

You can also do `pip install --user -e .` to install a local copy which is useful if you're trying the latest code from
[the cve-bin-tool github](https://github.com/intel/cve-bin-tool) or doing development. The [Contributor Documentation](https://github.com/intel/cve-bin-tool/blob/main/CONTRIBUTING.md) covers how to set up for local development in more detail.

Pip will install the python requirements for you, but for some types of extraction we use system libraries.  If you have difficulties extracting files, you may want to look at our [additional Requirements lists for Linux and Windows](#additional-requirements).

## Setting up an NVD_API_KEY

The major source of data for known vulnerabilities at this time is the National Vulnerability Database (NVD).  We recommend most users [Get an NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) and use it with cve-bin-tool to avoid timeouts, as access to the data is rate limited fairly heavily and many users report having difficulty downloading the data without a key.  There are [several ways to pass the NVD_API_KEY through to cve-bin-tool](#national-vulnerability-database-nvd).  The quickstart examples below show how to pass it through as a command-line option so that first-time users don't miss it but most users prefer to use [a config file or environment variable](#national-vulnerability-database-nvd) to avoid having to copy the key over and over again or to take advantage of secret storage in environments such as Github Actions.

CVE Binary Tool uses the NVD API but is not endorsed or certified by the NVD.

## Most popular usage options

### Finding known vulnerabilities using the binary scanner

To run the binary scanner on a directory or file:

```bash
cve-bin-tool --nvd-api-key <key> <directory/file>
```

> **Note**: That this option will also use any [language specific checkers](#language-specific-checkers) to find known vulnerabilities in components.
>
> You can also store the nvd-api-key in an environment variable rather than passing it through on the command line: [nvd_api_key instructions](#national-vulnerability-database-nvd).

### Finding known vulnerabilities in a list of components

To scan a comma-delimited (CSV) or JSON file which lists dependencies and versions:

```bash
cve-bin-tool --nvd-api-key <key> --input-file <filename>
```

> You can also store the nvd-api-key in an environment variable rather than passing it through on the command line: [nvd_api_key instructions](#national-vulnerability-database-nvd).

### Scanning an SBOM file for known vulnerabilities

To scan a software bill of materials file (SBOM):

```bash
cve-bin-tool --nvd-api-key <key> --sbom <sbom_filetype> --sbom-file <sbom_filename>
```

Valid SBOM types are [SPDX](https://spdx.dev/specifications/),
[CycloneDX](https://cyclonedx.org/specification/overview/), and [SWID](https://csrc.nist.gov/projects/software-identification-swid/guidelines).
Scanning of product names within an SBOM file is case insensitive.

> You can also store the nvd-api-key in an environment variable rather than passing it through on the command line: [nvd_api_key instructions](#national-vulnerability-database-nvd).

### Providing triage input

The `--triage-input-file` option can be used to add extra triage data like remarks, comments etc. while scanning a directory so that output will reflect this triage data and you can save time of re-triaging (Usage: `cve-bin-tool --triage-input-file test.vex /path/to/scan`).
The supported format is the [CycloneDX](https://cyclonedx.org/capabilities/vex/) VEX format which can be generated using the `--vex` option.

### Using the tool offline

Specifying the `--offline` option when running a scan ensures that cve-bin-tool doesn't attempt to download the latest database files or to check for a newer version of the tool.

Note that you will need to obtain a copy of the vulnerability data before the tool can run in offline mode. [The offline how-to guide contains more information on how to set up your database.](https://github.com/intel/cve-bin-tool/blob/main/doc/how_to_guides/offline.md)

## Output Options

The CVE Binary Tool provides console-based output by default. If you wish to provide another format, you can specify this and a filename on the command line using `--format`. The valid formats are CSV, JSON, console, HTML and PDF. The output filename can be specified using the `--output-file` flag.

You can also specify multiple output formats by using comma (',') as separator:

```bash
cve-bin-tool file -f csv,json,html -o report
```

Note: Please don't use spaces between comma (',') and the output formats.

The reported vulnerabilities can additionally be reported in the
Vulnerability Exchange (VEX) format by specifying `--vex` command line option.
The generated VEX file can then be used as a `--triage-input-file` to support
a triage process.

If you wish to use PDF support, you will need to install the `reportlab`
library separately.

If you intend to use PDF support when you install cve-bin-tool you can specify it and report lab will be installed as part of the cve-bin-tool install:

```console
pip install cve-bin-tool[PDF]
```

If you've already installed cve-bin-tool you can add reportlab after the fact
using pip:

```console
pip install --upgrade reportlab
```

Note that reportlab was taken out of the default cve-bin-tool install because
it has a known CVE associated with it
([CVE-2020-28463](https://nvd.nist.gov/vuln/detail/CVE-2020-28463)). The
cve-bin-tool code uses the recommended mitigations to limit which resources
added to PDFs, as well as additional input validation. This is a bit of a
strange CVE because it describes core functionality of PDFs: external items,
such as images, can be embedded in them, and thus anyone viewing a PDF could
load an external image (similar to how viewing a web page can trigger external
loads). There's no inherent "fix" for that, only mitigations where users of
the library must ensure only expected items are added to PDFs at the time of
generation.

Since users may not want to have software installed with an open, unfixable CVE
associated with it, we've opted to make PDF support only available to users who
have installed the library themselves. Once the library is installed, the PDF
report option will function.

## Full option list

Usage:
`cve-bin-tool <directory/file to scan>`

<pre>
options:
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-h---help">-h, --help</a>            show this help message and exit
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-e-exclude---exclude-exclude">-e EXCLUDE, --exclude</a> EXCLUDE
                        Comma separated Exclude directory path
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-v---version">-V, --version</a>         show program's version number and exit
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--disable-version-check">--disable-version-check</a>
                        skips checking for a new version
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--disable-validation-check">--disable-validation-check</a>
                        skips checking xml files against schema
  --offline             operate in offline mode
  --detailed            display detailed report

CVE Data Download:
  Arguments related to data sources and Cache Configuration

  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-n-jsonapiapi2---nvd-jsonapiapi2">-n {api,api2,json}, --nvd {api,api2,json}</a>
                        choose method for getting CVE lists from NVD
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-u-nowdailyneverlatest---update-nowdailyneverlatest">-u {now,daily,never,latest}, --update {now,daily,never,latest}</a>
                        update schedule for data sources and exploits database (default: daily)
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--nvd-api-key-nvd_api_key">--nvd-api-key NVD_API_KEY</a>
                        specify NVD API key (used to improve NVD rate limit)
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-d-nvdosvgad-nvdosvgad----disable-data-source-nvdosvgad-nvdosvgad-">-d {NVD,OSV} [{NVD,OSV} ...], --disable-data-source {NVD,OSV} [{NVD,OSV} ...]</a>
                        comma-separated list of data sources (GAD, NVD, OSV, REDHAT) to disable (default: NONE)

  --use-mirror USE_MIRROR
                        use an mirror to update the database

Input:
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#directory-positional-argument">directory</a>             directory to scan
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-i-input_file---input-file-input_file">-i INPUT_FILE, --input-file</a> INPUT_FILE
                        provide input filename
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--triage-input-file-input_file">--triage-input-file TRIAGE_INPUT_FILE</a>
                        provide input filename for triage data
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-c-config---config-config">-C CONFIG, --config CONFIG</a>
                        provide config file
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-l-package_list---package-list-package_list">-L PACKAGE_LIST, --package-list PACKAGE_LIST</a>
                        provide package list
  --sbom {spdx,cyclonedx,swid}
                        specify type of software bill of materials (sbom) (default: spdx)
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--sbom-file-sbom_file">--sbom-file SBOM_FILE</a>
                        provide sbom filename

Output:
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#quiet-mode">-q, --quiet</a>           suppress output
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#logging-modes">-l {debug,info,warning,error,critical}, --log {debug,info,warning,error,critical}</a>
                        log level (default: info)
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-o-output_file---output-file-output_file">-o OUTPUT_FILE, --output-file OUTPUT_FILE</a>
                        provide output filename (default: output to stdout)
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--html-theme-html_theme">--html-theme HTML_THEME</a>
                        provide custom theme directory for HTML Report
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-f-csvjsonconsolehtml---format-csvjsonconsolehtml">-f {csv,json,console,html,pdf}, --format {csv,json,console,html,pdf}</a>
                        update output format (default: console)
                        specify multiple output formats by using comma (',') as a separator
                        note: don't use spaces between comma (',') and the output formats.
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-c-cvss---cvss-cvss">-c CVSS, --cvss CVSS</a>  minimum CVSS score (as integer in range 0 to 10) to report (default: 0)
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-s-lowmediumhighcritical---severity-lowmediumhighcritical">-S {low,medium,high,critical}, --severity {low,medium,high,critical}</a>
                        minimum CVE severity to report (default: low)
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--report">--report</a>              Produces a report even if there are no CVE for the respective output format
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-a-distro_name-distro_version_name---available-fix-distro_name-distro_version_name">-A [<distro_name>-<distro_version_name>], --available-fix [<distro_name>-<distro_version_name>]</a>
                        Lists available fixes of the package from Linux distribution
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-b-distro_name-distro_version_name---backport-fix-distro_name-distro_version_name">-b [<distro_name>-<distro_version_name>], --backport-fix [<distro_name>-<distro_version_name>]</a>
                        Lists backported fixes if available from Linux distribution
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--affected-versions">--affected-versions</a>   Lists versions of product affected by a given CVE (to facilitate upgrades)
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--vex-vex_file">--vex VEX</a>             Provide vulnerability exchange (vex) filename
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--sbom-output-sbom_output">--sbom-output SBOM_OUTPUT</a>
                        provide software bill of materials (sbom) filename to generate
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--sbom-type">--sbom-type {spdx,cyclonedx}</a>
                        specify type of software bill of materials (sbom) to generate (default: spdx)
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--sbom-format">--sbom-format {tag,json,yaml}</a>
                        specify format of software bill of materials (sbom) to generate (default: tag)

Merge Report:
  Arguments related to Intermediate and Merged Reports

  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-a-intermediate_path---append-intermediate_path">-a [APPEND], --append [APPEND]</a>
                        save output as intermediate report in json format
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-t-tag---tag-tag">-t TAG, --tag TAG</a>     add a unique tag to differentiate between multiple intermediate reports
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-m-intermediate_reports---merge-intermediate_reports">-m MERGE, --merge MERGE</a>
                        comma separated intermediate reports path for merging
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-f-tags---filter-tags">-F FILTER, --filter FILTER</a>
                        comma separated tag string for filtering intermediate reports

Checkers:
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-s-skips---skips-skips">-s SKIPS, --skips SKIPS</a>
                        comma-separated list of checkers to disable
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-r-checkers---runs-checkers">-r RUNS, --runs RUNS</a>  comma-separated list of checkers to enable

Database Management:
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--export-export">--export EXPORT</a>       export database filename
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#--import-import">--import IMPORT</a>       import database filename

Exploits:
  --exploits            check for exploits from found cves

Deprecated:
  <a href="https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-x---extract">-x, --extract</a>         autoextract compressed files
   CVE Binary Tool autoextracts all compressed files by default now
</pre>

For further information about all of these options, please see [the CVE Binary Tool user manual](https://cve-bin-tool.readthedocs.io/en/latest/MANUAL.html).

> Note: For backward compatibility, we still support `csv2cve` command for producing CVEs from csv but we recommend using the `--input-file` command going forwards.

`-L` or `--package-list` option runs a CVE scan on installed packages listed in a package list. It takes a python package list (requirements.txt) or a package list of packages of systems that has dpkg, pacman or rpm package manager as an input for the scan. This option is much faster and detects more CVEs than the default method of scanning binaries.

You can get a package list of all installed packages in

- a system using dpkg package manager by running `dpkg-query -W -f '${binary:Package}\n' > pkg-list.txt`
- a system using pacman package manager by running `pacman -Qqe > pkg-list.txt`
- a system using rpm package manager by running `rpm -qa --queryformat '%{NAME}\n' > pkg-list.txt`

in the terminal and provide it as an input by running `cve-bin-tool -L pkg-list.txt` for a full package scan.

## Configuration

You can use `--config` option to provide configuration file for the tool. You can still override options specified in config file with command line arguments. See our sample config files in the
[test/config](https://github.com/intel/cve-bin-tool/blob/main/test/config/)

## Using CVE Binary Tool in GitHub Actions

If you want to integrate cve-bin-tool as a part of your github action pipeline.
You can checkout our example [github action](https://github.com/intel/cve-bin-tool/blob/main/doc/how_to_guides/cve_scanner_gh_action.yml).

## Data Sources

The following data sources are used to get CVE data to find CVEs for a package:

### [National Vulnerability Database](https://nvd.nist.gov/) (NVD)

This data source consists of majority of the CVE entries and is essential to provide vendor data for other data sources such as OSV, therefore disabling the download of CVE data from this source is not possible, `--disable-data-source "NVD"` only disables CVEs from displaying in output.

The National Vulnerability Database (NVD) has changed its access policy and it is now recommended that users obtain an NVD API Key to ensure access to the full database. The cve-bin-tool supports using an NVD API KEY for retrieving vulnerability data from the NVD.

NVD requires users to create and use an NVD_API_KEY to use their API. To set up an API_KEY ,please visit [Request an API Key](https://nvd.nist.gov/developers/request-an-api-key) .

There are three ways to set up the NVD API Key in cve-bin-tool:

- By using environment variable
- By defining it in config file
- By stating it in command line interface(cli)

By using environment variable

- Open a terminal window and navigate to the directory where you have installed cve-bin-tool.
- Enter the following command to set your NVD API key as an environment variable:

```bash
  export NVD_API_KEY=<your api key>
```

- Replace `<your api key>` with your actual NVD API key.
- You can verify that the environment variable has been set by entering the following command:

```bash
echo $NVD_API_KEY
```

- Now, when you run cve-bin-tool, it will automatically use the NVD API key that you have set as an environment variable.
  > **Note** : The steps to set environment variables may vary depending on the operating system you are using. The above steps are for Unix-based systems such as Linux and macOS. On Windows, you can set environment variables using the System Properties dialog or the Command Prompt.

By defining it in config file

- Open the cve-bin-tool configuration file (config.yaml or config.toml)
- Under the [nvd section, add the following line:

```bash
  api_key = your_api_key_here
```

- Replace `your_api_key_here` with your NVD API Key.
- Save the changes to the configuration file.
- which can be passed to the cve-bin-tool

```bash
 cve-bin-tool --config config.toml
```

By stating it in command line interface(cli)

- To set the flag `--nvd-api-key` to the API Key you have been provided.
- You can implement that in the following way :

```bash
cve-bin-tool --nvd-api-key your_api_key_here
```

Once you have set up your NVD API Key, cve-bin-tool will use it to retrieve vulnerability data from the NVD. This will ensure that you have access to the full database and will reduce the likelihood of encountering errors due to limited access.

If for any reason, the NVD API Key is not working, cve-bin-tool will automatically switch to the JSON fallback. However, it is highly recommended that you verify that your API Key is working properly to ensure access with the NVD database. To use the json method, use the flag [`-n json` or `--nvd json`](https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md#-n-jsonapi---nvd-jsonapi) . You can use it in the following way

```bash
cve-bin-tool --nvd-api-key your_api_key_here -n json
```

> **Note** : If you have problems downloading the initial data , it may be due to the NVD's current rate limiting scheme which block users entirely if they aren't using an API key.
>
> If you don't want to use the NVD API, you can also download their json files without setting up a key. Please note that this method is slower for getting updates but is more ideal if you just want to try out the `cve-bin-tool` for the first time.
>
> If the API key is not used, the time to access and download the data from the NVD database will be significantly increased due to the rate limiting algorithm implemented by the NVD. This algorithm limits the number of requests that can be made to the NVD database per unit time, and if this limit is exceeded, the user will be blocked from accessing the data for a period of time.
>
> So without an API key, users may experience slower download speeds and longer wait times for their requests to be processed, as they will be subject to these rate limits. Therefore, it is highly recommended to obtain and use an NVD API key for optimal performance and functionality when working with the cve-bin-tool.

### [Open Source Vulnerability Database](https://osv.dev/) (OSV)

This data source is based on the OSV schema from Google, and consists of CVEs from different ecosystems that might not be covered by NVD.
NVD is given priority if there are duplicate CVEs as some CVEs from OSV may not contain CVSS scores.
Using OSV will increase number of CVEs and time taken to update the database but searching database for vulnerabilities will have similar performance.

### [Gitlab Advisory Database](https://advisories.gitlab.com/) (GAD)

This data source consists of security advisories used by the GitLab dependency scanner.
The number of CVEs added from this data source is similar to OSV.

### [RedHat Security Database](https://access.redhat.com/security/data) (REDHAT)

This data source contains CVEs pertaining to RedHat Products.

Access to the data is subject to [Legal Notice](https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html/red_hat_security_data_api/legal-notice).

### [Curl Database](https://curl.se/) (Curl)

This data source provides the CVEs for the CURL product.

## Binary checker list

The following checkers are available for finding components in binary files:

<!--CHECKERS TABLE BEGIN-->
|   |  |  | Available checkers |  |  |  |
|--------------- |---------------- |------------------ |------------- |---------- |--------------- |----------------- |
| accountsservice |acpid |apache_http_server |apcupsd |apparmor |asn1c |assimp |
| asterisk |atftp |avahi |bash |bind |binutils |bird |
| bison |bluez |boinc |botan |bro |bubblewrap |busybox |
| bzip2 |c_ares |capnproto |ceph |chess |chrony |clamav |
| collectd |commons_compress |connman |cronie |cryptsetup |cups |curl |
| cvs |darkhttpd |davfs2 |dbus |dhclient |dhcpcd |dhcpd |
| dnsmasq |domoticz |dovecot |doxygen |dpkg |dropbear |e2fsprogs |
| elfutils |enscript |exim |exiv2 |expat |f2fs_tools |faad2 |
| fastd |ffmpeg |file |firefox |flac |freeradius |freerdp |
| fribidi |frr |gcc |gdb |gimp |git |glib |
| glibc |gmp |gnomeshell |gnupg |gnutls |gpgme |gpsd |
| graphicsmagick |grub2 |gstreamer |gupnp |gvfs |haproxy |harfbuzz |
| haserl |hdf5 |hostapd |hunspell |i2pd |icecast |icu |
| iperf3 |ipmitool |ipsec_tools |iptables |irssi |iucode_tool |jack2 |
| jacksondatabind |janus |jhead |json_c |kbd |keepalived |kerberos |
| kexectools |kodi |kubernetes |lftp |libarchive |libass |libbpg |
| libconfuse |libdb |libebml |libgcrypt |libgit2 |libical |libidn2 |
| libinput |libjpeg |libjpeg_turbo |libksba |liblas |libmatroska |libmemcached |
| libnss |libpcap |libraw |librsvg |librsync |libsamplerate |libseccomp |
| libsndfile |libsolv |libsoup |libsrtp |libssh |libssh2 |libtiff |
| libtomcrypt |libupnp |libvirt |libvncserver |libvorbis |libxslt |lighttpd |
| linux_kernel |lldpd |logrotate |lua |luajit |lxc |lynx |
| lz4 |mailx |mariadb |mdadm |memcached |minicom |minidlna |
| miniupnpc |miniupnpd |modsecurity |mosquitto |motion |mpv |msmtp |
| mtr |mutt |mysql |nano |nasm |nbd |ncurses |
| neon |nessus |netatalk |netkit_ftp |netpbm |nettle |nghttp2 |
| nginx |nmap |node |ntp |ntpsec |open_iscsi |open_vm_tools |
| openafs |opencv |openjpeg |openldap |opensc |openssh |openssl |
| openswan |openvpn |p7zip |pango |patch |pcre |pcre2 |
| pcsc_lite |perl |picocom |pigz |png |polarssl_fedora |poppler |
| postgresql |ppp |privoxy |procps_ng |proftpd |pspp |pure_ftpd |
| putty |python |qemu |qt |quagga |radare2 |radvd |
| raptor |rauc |rdesktop |rsync |rsyslog |rtl_433 |rtmpdump |
| runc |rust |samba |sane_backends |sdl |seahorse |shadowsocks_libev |
| snort |sofia_sip |speex |spice |sqlite |squashfs |squid |
| sslh |stellarium |strongswan |stunnel |subversion |sudo |suricata |
| sylpheed |syslogng |sysstat |systemd |tcpdump |tcpreplay |thrift |
| thttpd |thunderbird |timescaledb |tinyproxy |tor |tpm2_tss |transmission |
| trousers |u_boot |unbound |unixodbc |upx |util_linux |varnish |
| vim |vorbis_tools |vsftpd |webkitgtk |wget |wireshark |wolfssl |
| wpa_supplicant |xerces |xml2 |xscreensaver |yasm |zabbix |zeek |
| zlib |znc |zsh | | | | |
<!--CHECKERS TABLE END-->

All the checkers can be found in the checkers directory, as can the
[instructions on how to add a new checker](https://github.com/intel/cve-bin-tool/blob/main/cve_bin_tool/checkers/README.md).
Support for new checkers can be requested via
[GitHub issues](https://github.com/intel/cve-bin-tool/issues).

## Language Specific checkers

A number of checkers are available for finding vulnerable components in specific language packages.

### Java

The scanner examines the `pom.xml` file within a Java package archive to identify Java components. The package names and versions within the archive are used to search the database for vulnerabilities.

JAR, WAR and EAR archives are supported.

### Javascript

The scanner examines the `package-lock.json` file within a javascript application
to identify components. The package names and versions are used to search the database for vulnerabilities.

### Rust

The scanner examines the `Cargo.lock` file which is created by cargo to manage the dependencies of the project with their specific versions. The package names and versions are used to search the database for vulnerabilities.

### Ruby

The scanner examines the `Gemfile.lock` file which is created by bundle to manage the dependencies of the project with their specific versions. The package names and versions are used to search the database for vulnerabilities.

### R

The scanner examines the `renv.lock` file which is created by renv to manage the dependencies of the project with their specific versions. The package names and versions are used to search the database for vulnerabilities.

### Go

The scanner examines the `go.mod` file which is created by mod to manage the dependencies of the project with their specific versions. The package names and versions are used to search the database for vulnerabilities.

### Swift

The scanner examines the `Package.resolved` file which is created by the package manager to manage the dependencies of the project with their specific versions. The package names and versions are used to search the database for vulnerabilities.

### Python

The scanner examines the `PKG-INFO` and `METADATA` files for an installed Python package to extract the component name and version which
are used to search the database for vulnerabilities.
Support for scanning the `requirements.txt` file generated by pip is also present.

The tool supports the scanning of the contents of any Wheel package files (indicated with a file extension of .whl) and egg package files (indicated with a file extension of .egg).

The `--package-list` option can be used with a Python dependencies file `requirements.txt` to find the vulnerabilities in the list of components.

### Perl

The scanner examines the `cpanfile` file within a perl application to identify components. The package names and versions are used to search the database for vulnerabilities. 

The `cpanfile` must specify the version data for the vulnerability scanner to work. At this time packages without versions will be ignored. (Patches welcome to improve this behaviour in future!)

Here's an example of what a [`cpanfile`](https://github.com/intel/cve-bin-tool/blob/main/test/language_data/cpanfile) might look like.

## SBOM Generation

To generate a software bill of materials file (SBOM) ensure these options are included:

```bash
cve-bin-tool  --sbom-type <sbom_type> --sbom-format <sbom-format> --sbom-output <sbom_filename> <other scan options as required>
```

Valid SBOM types are [SPDX](https://spdx.dev/specifications/) and [CycloneDX](https://cyclonedx.org/specification/overview/).

The generated SBOM will include product name, version and supplier (where available). License information is not provided.

## Limitations

This scanner does not attempt to exploit issues or examine the code in greater
detail; it only looks for library signatures and version numbers. As such, it
cannot tell if someone has backported fixes to a vulnerable version, and it
will not work if library or version information was intentionally obfuscated.

This tool is meant to be used as a quick-to-run, easily-automatable check in a
non-malicious environment so that developers can be made aware of old libraries
with security issues that have been compiled into their binaries.

The tool does not guarantee that any vulnerabilities reported are actually present or exploitable, neither is it able to find all present vulnerabilities with a guarantee.

Users can add triage information to reports to mark issues as false positives, indicate that the risk has been mitigated by configuration/usage changes, and so on.

Triage details can be re-used on other projects so, for example, triage on a Linux base image could be applied to multiple containers using that image.

For more information and usage of triage information with the tool kindly have a look [here](https://cve-bin-tool.readthedocs.io/en/latest/MANUAL.html#triage-input-file-input-file).

If you are using the binary scanner capabilities, be aware that we only have a limited number of binary checkers (see table above) so we can only detect those libraries. Contributions of new checkers are always welcome! You can also use an alternate way to detect components (for example, a bill of materials tool such as [tern](https://github.com/tern-tools/tern)) and then use the resulting list as input to cve-bin-tool to get a more comprehensive vulnerability list.

The tool uses a vulnerability database in order to detect the present vulnerabilities, in case the database is not frequently updated (specially if the tool is used in offline mode), the tool would be unable to detect any newly discovered vulnerabilities. Hence it is highly advised to keep the database updated.

The tool does not guarantee that all vulnerabilities are reported as the tool only has access to a limited number of publicly available vulnerability databases.
Contributions to introduce new sources of data to the tool are always welcome.

Whilst some validation checks are performed on the data within the vulnerability database, the tool is unable to assert the quality of the data or correct any
discrepancies if the data is incomplete or inconsistent. This may result, for example, in some vulnerability reports where the severity is reported as UNKNOWN.

## Additional Requirements

To use the auto-extractor, you may need the following utilities depending on the type of [supported archive formats](#supported-archive-formats) you need to extract.

The utilities below are required to run the full test suite on Linux:

- `file`
- `strings`
- `tar`
- `unzip`
- `rpm2cpio`
- `cpio`
- `ar`
- `cabextract`

Most of these are installed by default on many Linux systems, but `cabextract` and
`rpm2cpio` in particular might need to be installed.

On windows systems, you may need:

- `ar`
- `7z`
- `Expand`
- `pdftotext`

Windows has `Expand` installed by default, but `ar` and `7z` might need to be installed.
If you want to run our test-suite or scan a zstd compressed file, We recommend installing this [7-zip-zstd](https://github.com/mcmilk/7-Zip-zstd)
fork of 7zip. We are currently using `7z` for extracting `jar`, `apk`, `msi`, `exe` and `rpm` files.
To install `ar` you can install MinGW (which has binutils as a part of it) from [here](https://www.mingw-w64.org/downloads/#msys2) and run the downloaded .exe file.

If you get an error about building libraries when you try to install from pip,
you may need to install the Windows build tools. The Windows build tools are
available for free from
<https://visualstudio.microsoft.com/visual-cpp-build-tools/>

If you get an error while installing brotlipy on Windows, installing the
compiler above should fix it.

`pdftotext` is required for running tests. (users of cve-bin-tool may not need it, developers likely will.) The best approach to install it on Windows involves using [conda](https://docs.conda.io/projects/conda/en/latest/user-guide/install/windows.html) (click [here](https://anaconda.org/conda-forge/pdftotext) for further instructions).

You can check [our CI configuration](https://github.com/intel/cve-bin-tool/blob/main/.github/workflows/testing.yml) to see what versions of python we're explicitly testing.

## Supported Archive Formats

The following archive formats are currently supported by the auto-extractor:

| Archive Format | File Extension |
|--|--|
| zip | .zip, .exe, .jar, .msi, .egg, .whl, .war, .ear |
| tar | .tar, .tgz, .tar.gz, .tar.xz, .tar.bz2 |
| deb | .deb, .ipk |
| rpm | .rpm |
| cab | .cab |
| apk | .apk |
| zst | .zst |
| pkg | .pkg |


## Feedback & Contributions

Bugs and feature requests can be made via [GitHub
issues](https://github.com/intel/cve-bin-tool/issues). Be aware that these issues are
not private, so take care when providing output to make sure you are not
disclosing security issues in other products.

Pull requests are also welcome via git.

- New contributors should read the [contributor guide](https://github.com/intel/cve-bin-tool/blob/main/CONTRIBUTING.md) to get started.
- Folk who already have experience contributing to open source projects may not need the full guide but should still use the [pull request checklist](https://github.com/intel/cve-bin-tool/blob/main/CONTRIBUTING.md#checklist-for-a-great-pull-request) to make things easy for everyone.

CVE Binary Tool contributors are asked to adhere to the [Python Community Code of Conduct](https://www.python.org/psf/conduct/). Please contact [Terri](https://github.com/terriko/) if you have concerns or questions relating to this code of conduct.

## Security Issues

Security issues with the tool itself can be reported to Intel's security
incident response team via
[https://intel.com/security](https://intel.com/security).

If in the course of using this tool you discover a security issue with someone
else's code, please disclose responsibly to the appropriate party.
