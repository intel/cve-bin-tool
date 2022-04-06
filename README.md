# CVE Binary Tool quick start / README

[![Build Status](https://github.com/intel/cve-bin-tool/workflows/cve-bin-tool/badge.svg?branch=main&event=push)](https://github.com/intel/cve-bin-tool/actions)
[![codecov](https://codecov.io/gh/intel/cve-bin-tool/branch/main/graph/badge.svg)](https://codecov.io/gh/intel/cve-bin-tool)
[![Gitter](https://badges.gitter.im/cve-bin-tool/community.svg)](https://gitter.im/cve-bin-tool/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![On ReadTheDocs](https://readthedocs.org/projects/cve-bin-tool/badge/?version=latest&style=flat)](https://cve-bin-tool.readthedocs.io/en/latest/)
[![On PyPI](https://img.shields.io/pypi/v/cve-bin-tool)](https://pypi.org/project/cve-bin-tool/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5380/badge)](https://bestpractices.coreinfrastructure.org/projects/5380)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/intel/cve-bin-tool.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/intel/cve-bin-tool/context:python)

The CVE Binary Tool is a free, open source tool to help you find known vulnerabilities in software, using data from the [National Vulnerability Database](https://nvd.nist.gov/) (NVD) list of [Common Vulnerabilities and Exposures](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures#:~:text=Common%20Vulnerabilities%20and%20Exposures%20(CVE)%20is%20a%20dictionary%20of%20common,publicly%20known%20information%20security%20vulnerabilities.) (CVEs).

The tool has two main modes of operation:

1. A binary scanner which helps you determine which packages may have been included as part of a piece of software.  There are around 100 checkers which focus on common, vulnerable open source components such as openssl, libpng, libxml2 and expat.
2. Tools for scanning known component lists in various formats, including .csv, several linux distribution package lists, language specific package scanners and several Software Bill of Materials (SBOM) formats.

It is intended to be used as part of your continuous integration system to enable regular vulnerability scanning and give you early warning of known issues in your supply chain.

For more details, see our [documentation](https://cve-bin-tool.readthedocs.io/en/latest/) or this [quickstart guide](https://cve-bin-tool.readthedocs.io/en/latest/README.html)  

- [CVE Binary Tool quick start / README](#cve-binary-tool-quick-start--readme)
  - [Installing CVE Binary Tool](#installing-cve-binary-tool)
  - [Most popular usage options](#most-popular-usage-options)
    - [Finding known vulnerabilities using the binary scanner](#finding-known-vulnerabilities-using-the-binary-scanner)
    - [Finding known vulnerabilities in a list of components](#finding-known-vulnerabilities-in-a-list-of-components)
    - [Scanning an SBOM file for known vulnerabilities](#scanning-an-sbom-file-for-known-vulnerabilities)
    - [Using the tool offline](#using-the-tool-offline)
  - [Output Options](#output-options)
  - [Full option list](#full-option-list)
  - [Configuration](#configuration)
  - [Using CVE Binary Tool in GitHub Actions](#using-cve-binary-tool-in-github-actions)
  - [Binary checker list](#binary-checker-list)
  - [Language Specific checkers](#language-specific-checkers)
    - [Java](#java)
    - [Javascript](#javascript)
    - [Python](#python)
  - [Limitations](#limitations)
  - [Requirements](#requirements)
  - [Feedback & Contributions](#feedback--contributions)
  - [Security Issues](#security-issues)

## Installing CVE Binary Tool

CVE Binary Tool can be installed using pip:

```console
pip install cve-bin-tool
```

You can also do `pip install --user -e .` to install a local copy which is useful if you're trying the latest code from
[the cve-bin-tool github](https://github.com/intel/cve-bin-tool) or doing development.  The [Contributor Documentation](https://github.com/intel/cve-bin-tool/blob/main/CONTRIBUTING.md) covers how to set up for local development in more detail.

## Most popular usage options

### Finding known vulnerabilities using the binary scanner

To run the binary scanner on a directory or file:

```bash
cve-bin-tool <directory/file>
```

Note that this option will also use any [language specific checkers](#language-specific-checkers) to find known vulnerabilities in components.  

### Finding known vulnerabilities in a list of components

To scan a comma-delimited (CSV) or JSON file which lists dependencies and versions:

```bash
cve-bin-tool --input-file <filename>
```

Note that the `--input-file` option can also be used to add extra triage data like remarks, comments etc. while scanning a directory so that output will reflect this triage data and you can save time of re-triaging (Usage: `cve-bin-tool -i=test.csv /path/to/scan`).
A VEX file (which may be created using the `--vex` command line option) can also be used as a triage file. A VEX file
is detected if the file suffix is '.vex'.

### Scanning an SBOM file for known vulnerabilities

To scan a software bill of materials file (SBOM):

```bash
cve-bin-tool  --sbom <sbom_filetype> --sbom-file <sbom_filename>
```

Valid SBOM types are [SPDX](https://spdx.dev/specifications/),
[CycloneDX](https://cyclonedx.org/specification/overview/), and [SWID](https://csrc.nist.gov/projects/software-identification-swid/guidelines).

### Using the tool offline

Specifying the `--offline` option when running a scan ensures that cve-bin-tool doesn't attempt to download the latest database files or to check for a newer version of the tool.

Note that you will need to obtain a copy of the vulnerability data before the tool can run in offline mode. [The offline how-to guide contains more information on how to set up your database.](https://github.com/intel/cve-bin-tool/blob/main/doc/how_to_guides/offline.md)

## Output Options

The CVE Binary Tool provides console-based output by default.  If you wish to provide another format, you can specify this and a filename on the command line using `--format`.  The valid formats are CSV, JSON, console, HTML and PDF.  The output filename can be specified using the `--output-file` flag.

The reported vulnerabilities can additionally be reported in the
Vulnerability Exchange (VEX) format by specifying `--vex` command line option.
The generated VEX file can then be used as an `--input-file` to support
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
([CVE-2020-28463](https://nvd.nist.gov/vuln/detail/CVE-2020-28463)).  The
cve-bin-tool code uses the recommended mitigations to limit which resources
added to PDFs, as well as additional input validation.  This is a bit of a
strange CVE because it describes core functionality of PDFs: external items,
such as images, can be embedded in them, and thus anyone viewing a PDF could
load an external image (similar to how viewing a web page can trigger external
loads).  There's no inherent "fix" for that, only mitigations where users of
the library must ensure only expected items are added to PDFs at the time of
generation.

Since users may not want to have software installed with an open, unfixable CVE
associated with it, we've opted to make PDF support only available to users who
have installed the library themselves.  Once the library is installed, the PDF
report option will function.

## Full option list

Usage:
`cve-bin-tool <directory/file to scan>`

    optional arguments:
      -h, --help            show this help message and exit
      -e, --exclude         exclude path while scanning
      -V, --version         show program's version number and exit
      --disable-version-check
                            skips checking for a new version
      --disable-validation-check
                            skips checking xml files against schema
      --offline             operate in offline mode							

    CVE Data Download:
      -n {json,api}, --nvd {json,api}
                            choose method for getting CVE lists from NVD
      -u {now,daily,never,latest}, --update {now,daily,never,latest}
                            update schedule for NVD database (default: daily)
      --nvd-api-key NVD_API_KEY
                        specify NVD API key (used to improve NVD rate limit)

    Input:
      directory             directory to scan
      -i INPUT_FILE, --input-file INPUT_FILE
                            provide input filename
      -C CONFIG, --config CONFIG
                            provide config file
      -L PACKAGE_LIST, --package-list PACKAGE_LIST
                        provide package list
      --sbom {spdx,cyclonedx,swid}
                        specify type of software bill of materials (sbom)
                        (default: spdx)
      --sbom-file SBOM_FILE
                        provide sbom filename

    Output:
      -q, --quiet           suppress output
      -l {debug,info,warning,error,critical}, --log {debug,info,warning,error,critical}
                            log level (default: info)
      -o OUTPUT_FILE, --output-file OUTPUT_FILE
                            provide output filename (default: output to stdout)  
      --html-theme HTML_THEME
                            provide custom theme directory for HTML Report
      -f {csv,json,console,html,pdf}, --format {csv,json,console,html,pdf}
                            update output format (default: console)
      -c CVSS, --cvss CVSS  minimum CVSS score (as integer in range 0 to 10) to
                            report (default: 0)
      -S {low,medium,high,critical}, --severity {low,medium,high,critical}
                            minimum CVE severity to report (default: low)
      --report              Produces a report even if there are no CVE for the
                            respective output format
      -A [<distro_name>-<distro_version_name>], --available-fix [<distro_name>-<distro_version_name>]
                            Lists available fixes of the package from Linux distribution
      -b [<distro_name>-<distro_version_name>], --backport-fix [<distro_name>-<distro_version_name>]
                            Lists backported fixes if available from Linux distribution
      --affected-versions   Lists versions of product affected by a given CVE (to facilitate upgrades)
      --vex VEX             Provide vulnerability exchange (vex) filename
    
    Merge Report:
      -a INTERMEDIATE_PATH, --append INTERMEDIATE_PATH      
                            provide path for saving intermediate report 
      -t TAG, --tag TAG     provide a tag to differentiate between multiple intermediate reports
      -m INTERMEDIATE_REPORTS, --merge INTERMEDIATE_REPORTS           
                            comma separated intermediate reports path for merging
      -F TAGS, --filter TAGS           
                            comma separated tags to filter out intermediate reports
    
    Checkers:
      -s SKIPS, --skips SKIPS
                            comma-separated list of checkers to disable
      -r RUNS, --runs RUNS  comma-separated list of checkers to enable

    Deprecated:
       -x, --extract        autoextract compressed files
       CVE Binary Tool autoextracts all compressed files by default now

For further information about all of these options, please see [the CVE Binary Tool user manual](https://cve-bin-tool.readthedocs.io/en/latest/MANUAL.html).

> Note: For backward compatibility, we still support `csv2cve` command for producing CVEs from csv but we recommend using the `--input-file` command going forwards.

`-L` or `--package-list` option runs a CVE scan on installed packages listed in a package list. It takes a python package list (requirements.txt) or a package list of packages of systems that has dpkg, pacman or rpm package manager as an input for the scan. This option is much faster and detects more CVEs than the default method of scanning binaries.

You can get a package list of all installed packages in

- a system using dpkg package manager by running `dpkg-query -W -f '${binary:Package}\n' > pkg-list`
- a system using pacman package manager by running `pacman -Qqe > pkg-list`
- a system using rpm package manager by running `rpm -qa --queryformat '%{NAME}\n' > pkg-list`
  
in the terminal and provide it as an input by running `cve-bin-tool -L pkg-list` for a full package scan.

## Configuration

You can use `--config` option to provide configuration file for the tool. You can still override options specified in config file with command line arguments. See our sample config files in the
[test/config](https://github.com/intel/cve-bin-tool/blob/main/test/config/)

## Using CVE Binary Tool in GitHub Actions

If you want to integrate cve-bin-tool as a part of your github action pipeline.
You can checkout our example [github action](https://github.com/intel/cve-bin-tool/blob/main/doc/how_to_guides/cve_scanner_gh_action.yml).

## Binary checker list

The following checkers are available for finding components in binary files:

<!--CHECKERS TABLE BEGIN-->
|   |  |  | Available checkers |  |  |  |
|--------------- |---------- |---------- |------------ |--------------- |------------- |------------- |
| accountsservice |avahi |bash |bind |binutils |bolt |bubblewrap |
| busybox |bzip2 |cronie |cryptsetup |cups |curl |dbus |
| dnsmasq |dovecot |dpkg |enscript |expat |ffmpeg |freeradius |
| ftp |gcc |gimp |glibc |gnomeshell |gnupg |gnutls |
| gpgme |gstreamer |gupnp |haproxy |hdf5 |hostapd |hunspell |
| icecast |icu |irssi |kbd |kerberos |kexectools |libarchive |
| libbpg |libdb |libebml |libgcrypt |libical |libjpeg_turbo |liblas |
| libnss |librsvg |libseccomp |libsndfile |libsolv |libsoup |libsrtp |
| libssh2 |libtiff |libvirt |libvncserver |libxslt |lighttpd |logrotate |
| lua |mariadb |mdadm |memcached |mtr |mysql |nano |
| ncurses |nessus |netpbm |nginx |node |ntp |open_vm_tools |
| openafs |openjpeg |openldap |openssh |openssl |openswan |openvpn |
| p7zip |pcsc_lite |pigz |png |polarssl_fedora |poppler |postgresql |
| pspp |python |qt |radare2 |rsyslog |samba |sane_backends |
| sqlite |strongswan |subversion |sudo |syslogng |systemd |tcpdump |
| trousers |varnish |webkitgtk |wireshark |wpa_supplicant |xerces |xml2 |
| zlib |zsh | | | | | |
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


### Python

The scanner examines the `PKG-INFO` and `METADATA` files for an installed Python package to extract the component name and version which
are used to search the database for vulnerabilities.

The tool supports the scanning of the contents of any Wheel package files (indicated with a file extension of .whl) and egg package files (indicated with a file extension of .egg).

The `--package-list` option can be used with a Python dependencies file `requirements.txt` to find the vulnerabilities in the list of components.

## Limitations

This scanner does not attempt to exploit issues or examine the code in greater
detail; it only looks for library signatures and version numbers.  As such, it
cannot tell if someone has backported fixes to a vulnerable version, and it
will not work if library or version information was intentionally obfuscated.

This tool is meant to be used as a quick-to-run, easily-automatable check in a
non-malicious environment so that developers can be made aware of old libraries
with security issues that have been compiled into their binaries.

The tool does not guarantee that any vulnerabilities reported are actually present or exploitable, neither is it able to find all present vulnerabilities with a guarantee.

Users can add triage information to reports to mark issues as false positives, false negatives, indicate that the risk has been mitigated by configuration/usage changes, and so on.  

Triage details can be re-used on other projects so, for example, triage on a Linux base image could be applied to multiple containers using that image.

For more information and usage of triage information with the tool kindly have a look [here](https://cve-bin-tool.readthedocs.io/en/latest/MANUAL.html#i-input-file-input-file-input-file).

If you are using the binary scanner capabilities, be aware that we only have a limited number of binary checkers (see table above) so we can only detect those libraries. Contributions of new checkers are always welcome! You can also use an alternate way to detect components (for example, a bill of materials tool such as [tern](https://github.com/tern-tools/tern)) and then use the resulting list as input to cve-bin-tool to get a more comprehensive vulnerability list.

The tool uses a vulnerability database in order to detect the present vulnerabilities, in case the database is not frequently updated (specially if the tool is used in offline mode), the tool would be unable to detect any newly discovered vulnerabilities. Hence it is highly advised to keep the database updated.

## Requirements

To use the auto-extractor, you may need the following utilities depending on the
type of file you need to extract. The utilities below are required to run the full
test suite on Linux:

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

Windows has `ar` and `Expand` installed by default, but `7z` in particular might need to be installed.
If you want to run our test-suite or scan a zstd compressed file, We recommend installing this [7-zip-zstd](https://github.com/mcmilk/7-Zip-zstd)
fork of 7zip. We are currently using `7z` for extracting `jar`, `apk`, `msi`, `exe` and `rpm` files.

If you get an error about building libraries when you try to install from pip,
you may need to install the Windows build tools. The Windows build tools are
available for free from
<https://visualstudio.microsoft.com/visual-cpp-build-tools/>

If you get an error while installing brotlipy on Windows, installing the
compiler above should fix it.

`pdftotext` is required for running tests.  (users of cve-bin-tool may not need it, developers likely will.) The best approach to install it on Windows involves using  [conda](https://docs.conda.io/projects/conda/en/latest/user-guide/install/windows.html) (click [here](https://anaconda.org/conda-forge/pdftotext) for further instructions).

You can check [our CI configuration](https://github.com/intel/cve-bin-tool/blob/main/.github/workflows/testing.yml) to see what versions of python we're explicitly testing.

## Feedback & Contributions

Bugs and feature requests can be made via [GitHub
issues](https://github.com/intel/cve-bin-tool/issues).  Be aware that these issues are
not private, so take care when providing output to make sure you are not
disclosing security issues in other products.

Pull requests are also welcome via git.  

- New contributors should read the [contributor guide](https://github.com/intel/cve-bin-tool/blob/main/CONTRIBUTING.md) to get started.
- Folk who already have experience contributing to open source projects may not need the full guide but should still use the [pull request checklist](https://github.com/intel/cve-bin-tool/blob/main/CONTRIBUTING.md#checklist-for-a-great-pull-request) to make things easy for everyone.

## Security Issues

Security issues with the tool itself can be reported to Intel's security
incident response team via
[https://intel.com/security](https://intel.com/security).

If in the course of using this tool you discover a security issue with someone
else's code, please disclose responsibly to the appropriate party.
