CVE Binary Tool
===============

[![Build Status](https://github.com/intel/cve-bin-tool/workflows/cve-bin-tool/badge.svg?branch=master&event=push)](https://github.com/intel/cve-bin-tool/actions)
[![codecov](https://codecov.io/gh/intel/cve-bin-tool/branch/master/graph/badge.svg)](https://codecov.io/gh/intel/cve-bin-tool)
[![Gitter](https://badges.gitter.im/cve-bin-tool/community.svg)](https://gitter.im/cve-bin-tool/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)
[![On PyPI](https://img.shields.io/pypi/v/cve-bin-tool)](https://pypi.org/project/cve-bin-tool/)


The CVE Binary Tool scans for a number of common, vulnerable open source
components (openssl, libpng, libxml2, expat and a few others) to let you know
if a given directory or binary file includes common libraries with known
vulnerabilities.  (If you have a list of components with versions and want a
list of CVEs, check out
[csv2cve](https://github.com/intel/cve-bin-tool#csv2cve) below.)

Usage:
`cve-bin-tool <flags> <path to directory>`

You can also do `python -m cve_bin_tool.cli <flags> <path to directory>` which is useful if you're trying the latest code from [the cve-bin-tool github](https://github.com/intel/cve-bin-tool/compare).


```
  -h, --help            show help message and exit
  -V, --version         show program's version number and exit


  Output options:
  -q, --quiet           suppress output
  -l {debug,info,warning,error,critical}, --log {debug,info,warning,error,critical}
                        log level. The default log level is info
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        provide output filename (default: output to stdout)
  -f {csv,json,console}, --format {csv,json,console}
                        update output format (default: console)


  Functional options:
  -x, --extract         autoextract compressed files
  -s SKIPS, --skips SKIPS
                        comma-separated list of checkers to disable
  -r CHECKERS, --runs CHECKERS
                        comma-separated list of checkers to enable
  -m, --multithread     enable multithread
  -u {now,daily,never}, --update {now,daily,never}
                        update schedule for NVD database. Default is daily.
```

The 0.3.1 release is intended to be the last release to officially support
python 2.7; please switch to python 3.6+ for future releases and to use the
development tree.  You can check [our CI
configuration](https://github.com/intel/cve-bin-tool/blob/master/.github/workflows/pythonapp.yml)
to see what versions of python we're explicitly testing.

This readme is intended to be a quickstart guide for using the tool.  If you
require more information, there is also a [user manual](MANUAL.md) available.

How it works
------------

This scanner looks at the strings found in binary files to see if they
match certain vulnerable versions of the following libraries and tools:

* binutils
* bluez
* bzip2
* curl
* expat
* ffmpeg
* gnutls
* gstreamer
* hostapd
* icu
* kerberos
* libcurl
* libdb
* libgcrypt
* libjpeg
* libnss
* libtiff
* ncurses
* ngnix
* node.js
* openssh
* openssl
* png
* python
* rsyslog
* sqlite
* strongswan
* syslogng
* systemd
* varnish
* xerces
* xml2
* zlib

All the checkers can be found in the checkers directory, as can the
[instructions on how to add a new checker](cve_bin_tool/checkers/README.md).
Support for new checkers can be requested via
[GitHub issues](https://github.com/intel/cve-bin-tool/issues).

Limitations
-----------

This scanner does not attempt to exploit issues or examine the code in greater
detail; it only looks for library signatures and version numbers.  As such, it
cannot tell if someone has backported fixes to a vulnerable version, and it
will not work if library or version information was intentionally obfuscated.

This tool is meant to be used as a quick-to-run, easily-automatable check in a
non-malicious environment so that developers can be made aware of old libraries
with security issues that have been compiled into their binaries.

Requirements
------------

To use the auto-extractor, you may need the following utilities depending on the
type of file you need to extract. Belows are required to run the full
test suite on linux:

* `ar`
* `cabextract`
* `cpio`
* `rpm2cpio`

Most of these are installed by default on many Linux systems, but `cabextract` and
`rpm2cpio` in particular might need to be installed.

On windows systems, you may need:

* `ar`
* `7z`
* `Expand`

Windows has `ar` and `Expand` installed in default, but `7z` in particular might need to be installed.  (7z is used only for rpm extraction, which is used heavily in our test suite, but if you're not scanning rpm files on windows you may be able to do without.)

CSV2CVE
-------

The CVE Binary Tool package also includes a tool called `csv2cve` which is a helper tool that allows you to search the local database for a list of known products.  This can be useful if the list of products is known.

Usage:
`csv2cve <csv_file>`

The CSV file must contain the following columns: `vendor,product,version` where the vendor and product names are exact matches to the strings in the National Vulnerability Database.  You can read more about how to find the correct string in [the checker documentation](https://github.com/intel/cve-bin-tool/blob/master/cve_bin_tool/checkers/README.md), and the [csv2cve manual](https://github.com/intel/cve-bin-tool/blob/master/CSV2CVE.md) has more information on using this tool.

Note that `csv2cve`, unlike `cve-bin-tool`, will work on *any* product known in the National Vulnerability Database, not only those that have checkers written.

Feedback & Contributions
------------------------

Bugs and feature requests can be made via [GitHub
issues](https://github.com/intel/cve-bin-tool).  Be aware that these issues are
not private, so take care when providing output to make sure you are not
disclosing security issues in other products.

Pull requests are also welcome via git.

The CVE Binary Tool uses [the Black python code
formatter](https://github.com/python/black) to keep coding style consistent;
you may wish to have it installed to make pull requests easier.

Security Issues
---------------

Security issues with the tool itself can be reported to Intel's security
incident response team via
[https://intel.com/security](https://intel.com/security).

If in the course of using this tool you discover a security issue with someone
else's code, please disclose responsibly to the appropriate party.

