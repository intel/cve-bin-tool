# CVE Binary Tool quick start / README

[![Build Status](https://github.com/intel/cve-bin-tool/workflows/cve-bin-tool/badge.svg?branch=master&event=push)](https://github.com/intel/cve-bin-tool/actions)
[![codecov](https://codecov.io/gh/intel/cve-bin-tool/branch/master/graph/badge.svg)](https://codecov.io/gh/intel/cve-bin-tool)
[![Gitter](https://badges.gitter.im/cve-bin-tool/community.svg)](https://gitter.im/cve-bin-tool/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)
[![On PyPI](https://img.shields.io/pypi/v/cve-bin-tool)](https://pypi.org/project/cve-bin-tool/)

The CVE Binary Tool scans for a number of common, vulnerable open source 
components such as openssl, libpng, libxml2, and expat to let you know 
if a given directory or binary file includes common libraries with 
known vulnerabilities., known as CVEs ([Common Vulnerabilities and Exposures](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures#:~:text=Common%20Vulnerabilities%20and%20Exposures%20(CVE)%20is%20a%20dictionary%20of%20common,publicly%20known%20information%20security%20vulnerabilities.)).

See our [documentation](https://cve-bin-tool.readthedocs.io/en/latest/) and [quickstart guide](https://cve-bin-tool.readthedocs.io/en/latest/README.html)  
Usage:
`cve-bin-tool  `

You can also do `python -m cve_bin_tool.cli` 
which is useful if you're trying the latest code from 
[the cve-bin-tool github](https://github.com/intel/cve-bin-tool).


    optional arguments:
      -e, --exclude         exclude path while scanning
      -h, --help            show this help message and exit
      -V, --version         show program's version number and exit
      -u {now,daily,never,latest}, --update {now,daily,never,latest}
                            update schedule for NVD database (default: daily)
      --disable-version-check
                            skips checking for a new version
      
    Input:
      directory             directory to scan
      -i INPUT_FILE, --input-file INPUT_FILE
                            provide input filename
      -C CONFIG, --config CONFIG
                            provide config file

    Output:
      -q, --quiet           suppress output
      -l {debug,info,warning,error,critical}, --log {debug,info,warning,error,critical}
                            log level (default: info)
      -o OUTPUT_FILE, --output-file OUTPUT_FILE
                            provide output filename (default: output to stdout)
      --html-theme HTML_THEME
                            provide custom theme directory for HTML Report
      -f {csv,json,console,html}, --format {csv,json,console,html}
                            update output format (default: console)
      -c CVSS, --cvss CVSS  minimum CVSS score (as integer in range 0 to 10) to
                            report (default: 0)
      -S {low,medium,high,critical}, --severity {low,medium,high,critical}
                            minimum CVE severity to report (default: low)

    Checkers:
      -s SKIPS, --skips SKIPS
                            comma-separated list of checkers to disable
      -r RUNS, --runs RUNS  comma-separated list of checkers to enable

    Deprecated:
       -x, --extract        autoextract compressed files
       CVE Binary Tool autoextracts all compressed files by default now


Note that if the CVSS and Severity flags are both specified, the CVSS flag takes precedence.

`--input-file` extends the functionality of *csv2cve* for other formats like JSON.  It also allows cve-bin-tool to specify triage data so you can group issues which may have been mitigated (through patches, configuration, or other methods not detectable by our version scanning method) or mark false positives.  Triage data can be re-used and applied to multiple scans.  You can provide either CSV or JSON file as input_file with vendor, product and version fields. You can also add optional fields like remarks, comments, cve_number, severity.

Note that you can use `-i` or `--input-file` option to produce list of CVEs found in given vendor, product and version fields (Usage: `cve-bin-tool -i=test.csv`) or supplement extra triage data like remarks, comments etc. while scanning directory so that output will reflect this triage data and you can save time of re-triaging (Usage: `cve-bin-tool -i=test.csv /path/to/scan`).

> Note: For backward compatibility, we still support `csv2cve` command for producing CVEs from csv but we recommend using new `--input-file` command instead.

You can use `--config` option to provide configuration file for the tool. You can still override options specified in config file with command line arguments. See our sample config files in the 
[test/config](https://github.com/intel/cve-bin-tool/blob/master/test/config/)

The 0.3.1 release is intended to be the last release to officially support
python 2.7; please switch to python 3.6+ for future releases and to use the
development tree. You can check [our CI configuration](https://github.com/intel/cve-bin-tool/blob/master/.github/workflows/pythonapp.yml) to see what versions of python we're explicitly testing.

If you want to integrate cve-bin-tool as a part of your github action pipeline. 
You can checkout our example [github action](https://github.com/intel/cve-bin-tool/blob/master/doc/how_to_guides/cve_scanner_gh_action.yml). 

This readme is intended to be a quickstart guide for using the tool.  If you
require more information, there is also a [user manual](https://github.com/intel/cve-bin-tool/blob/master/doc/MANUAL.md) available.

## How it works

This scanner looks at the strings found in binary files to see if they
match certain vulnerable versions of the following libraries and tools:

|          |           |                | Available checkers |            |            |         |
| -------- | --------- | ---------------| ------------------ | ---------- | ---------- | ------- |
| avahi    | bash      | bind           | binutils           | busybox    | bzip2      | cups    |
| curl     | dovecot   | expat          | ffmpeg             | freeradius | gcc        | gimp    | 
| gnutls   | glibc     | gstreamer      | haproxy            | hostapd    | icecast    | icu     |
| irssi    | kerberos  | libarchive     | libdb              | libgcrypt  | libjpeg    | libnss  |
| libtiff  | libvirt   | lighttpd       | mariadb            | memcached  | ncurses    | nessus  |
| netpbm   | nginx     | node           | openafs            | openldap   | openssh    | openssl |
| openswan | openvpn   | png            | polarssl_fedora    | postgresql | python     | qt      |
| radare2  | rsyslog   | samba          | sqlite             | strongswan | syslogng   | systemd |
| tcpdump  | varnish   | wireshark      | xerces             | xml2       | zlib       |         |

All the checkers can be found in the checkers directory, as can the
[instructions on how to add a new checker](cve_bin_tool/checkers/README.md).
Support for new checkers can be requested via
[GitHub issues](https://github.com/intel/cve-bin-tool/issues).

## Limitations

This scanner does not attempt to exploit issues or examine the code in greater
detail; it only looks for library signatures and version numbers.  As such, it
cannot tell if someone has backported fixes to a vulnerable version, and it
will not work if library or version information was intentionally obfuscated.

This tool is meant to be used as a quick-to-run, easily-automatable check in a
non-malicious environment so that developers can be made aware of old libraries
with security issues that have been compiled into their binaries.

## Requirements

To use the auto-extractor, you may need the following utilities depending on the
type of file you need to extract. The utilities below are required to run the full
test suite on Linux:

-   `file`
-   `strings`
-   `tar`
-   `unzip`
-   `rpm2cpio`
-   `cpio`
-   `ar`
-   `cabextract`

Most of these are installed by default on many Linux systems, but `cabextract` and
`rpm2cpio` in particular might need to be installed.

On windows systems, you may need:

-   `ar`
-   `7z`
-   `Expand`

Windows has `ar` and `Expand` installed in default, but `7z` in particular might need to be installed.
If you want to run our test-suite or scan a zstd compressed file, We recommend installing this [7-zip-zstd](https://github.com/mcmilk/7-Zip-zstd)
fork of 7zip. We are currently using `7z` for extracting `jar`, `apk`, `msi`, `exe` and `rpm` files.


If you get an error about building libraries when you try to install from pip,
you may need to install the Windows build tools. The Windows build tools are
available for free from
<https://visualstudio.microsoft.com/visual-cpp-build-tools/>

If you get an error while installing brotlipy on Windows, installing the
compiler above should fix it.

## Feedback & Contributions

Bugs and feature requests can be made via [GitHub
issues](https://github.com/intel/cve-bin-tool/issues).  Be aware that these issues are
not private, so take care when providing output to make sure you are not
disclosing security issues in other products.

Pull requests are also welcome via git.

The CVE Binary Tool uses [the Black python code
formatter](https://github.com/python/black) to keep coding style consistent;
you may wish to have it installed to make pull requests easier.  We've provided a pre-commit hook (in `.pre-commit.config.yaml`) so if you want to have the check run locally before you commit, you can install pre-commit and install the hook as follows from the main cve-bin-tool directory:

    pip install pre-commit
    pre-commit install

## Security Issues

Security issues with the tool itself can be reported to Intel's security
incident response team via
[https://intel.com/security](https://intel.com/security).

If in the course of using this tool you discover a security issue with someone
else's code, please disclose responsibly to the appropriate party.
