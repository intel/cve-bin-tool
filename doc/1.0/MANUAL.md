Table of Contents
-----------------
- [CVE checker for binary code User Manual](#CVE-checker-for-binary-code-User-Manual)
  - [How it works](#How-it-works)
  - [Installing](#Installing)
  - [Fixing Known Issues / What should I do if it finds something?](#Fixing-Known-Issues--What-should-I-do-if-it-finds-something)
  - [Limitations](#Limitations)
  - [Options:](#Options)
    - [-x, --extract](#-x---extract)
    - [-s SKIPS, --skips SKIPS](#-s-SKIPS---skips-SKIPS)
    - [-r CHECKERS, --runs CHECKERS](#-r-CHECKERS---runs-CHECKERS)
    - [-m, --multithread enable multithread](#-m---multithread-enable-multithread)
    - [-u {now,daily,never}, --update {now,daily,never}](#-u-nowdailynever---update-nowdailynever)
  - [Output modes](#Output-modes)
      - [Default Mode](#Default-Mode)
    - [Quiet Mode](#Quiet-Mode)
    - [Logging modes](#Logging-modes)
  - [Feedback & Contributions](#Feedback--Contributions)
  - [Security Issues](#Security-Issues)


CVE checker for binary code User Manual
=======================================

This tool scans for a number of common, vulnerable open source components
(openssl, libpng, libxml2, expat and a few others) to let you know if your
system includes common libraries with known vulnerabilities, known as CVEs
(Common Vulnerabilities and Exposures).

Usage:
`cve-bin-tool <flags> <path to directory>`

Possible output levels:
```
  -q, --quiet           suppress output
  -l {debug,info,warning,error,critical}, --log {debug,info,warning,error,critical}
                        log level
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        provide output filename (default: output to stdout)
  -f {csv,json,console}, --format {csv,json,console}
                        update output format (default: console)
```
Other options:
```
  -h, --help            show help message and exit
  -V, --version         show program's version number and exit
  -x, --extract         autoextract compressed files
  -s SKIPS, --skips SKIPS
                        comma-separated list of checkers to disable
  -r CHECKERS, --runs CHECKERS
                        comma-separated list of checkers to enable
  -m, --multithread     enable multithread
  -u {now,daily,never}, --update {now,daily,never}
                        update schedule for NVD database. Default is daily.
```

Available checkers: `bluez, curl,  expat, ffmpeg, gnutls, icu, kerberos, libcurl, libdb, libgcrypt, libjpeg,
libnss, libtiff, node, openssh, openssl, png, python, sqlite, systemd, xerces, xml2, zlib
`

For a quick overview of usage and how it works, you can also see [the readme file](README.md).


How it works
------------
This scanner looks at the strings found in binary files to see if they
match vulnerable versions of a small set of popular open source libraries.

It does not attempt to exploit issues or examine code in greater detail.
As such, it cannot tell if someone has backported fixes to an otherwise
vulnerable version, it merely provides a mapping between strings, versions, and
known CVEs.

A [list of currently available checkers](https://github.com/intel/cve-bin-tool/tree/master/cve_bin_tool/checkers) can be found in the checkers
directory, as can the [instructions on how to add a new
checker](cve_bin_tool/checkers/README.md).  Support for new checkers can be requested
via [GitHub
issues](https://github.com/intel/cve-bin-tool/issues).
(Please note, you will need to be logged in to add a new issue.)


This tool gives a list of CVE numbers.  For those not familiar with the process, these can be looked up using a number of different tools, such as the [vulnerability search on the CVE Details website](https://www.cvedetails.com/vulnerability-search.php).  Each CVE filed contains a short summary of the issue, a set of severity scores that are combined to make a CVSS score, a list of products known to be affected, and links to more information (which may include links to sample exploits as well as patches to fix the issue).

Installing
----------

`cve-bin-tool` can be installed via pip. If your `PATH` environment variable is
properly configured, installation will result in `cve-bin-tool` being accessible
globally. If not you can treat `cve-bin-tool` as `python -m cve_bin_tool.cli` in
the documentation.

```console
pip install -U cve-bin-tool
```

If you want the latest and greatest between releases you can grab from GitHub.

```console
pip install -U git+https://github.com/intel/cve-bin-tool
```

CVE Binary Tool relies on a few command line utilities which are usually present
on GNU/Linux systems but you may need to install.

- file
- strings
- tar
- unzip
- rpm2cpio
- cpio
- ar
- cabextract

On Windows, it requires
- Extract 
- ar
- 7zip
  

Fixing Known Issues / What should I do if it finds something?
-------------------------------------------------------------

The most recommended way to fix a given CVE is to upgrade the package to a
non-vulnerable version.  Ideally, a CVE is only made public after a fix is
available, although this is not always the case.

If this is not possible for some reason, search for the CVE number to get
information on possible workarounds and patches that could be backported to
other versions.  Note that neither workarounds nor backported fixes can be
detected by this tool, so your binary will continue to show up as vulnerable
even though it may now be safely mitigated and the result a false positive.

Limitations
-----------

The last release of this tool to support python 2.7 is 0.3.1.  Please use
python 3.6+ for development and future versions.   Linux and Windows are
supported, as is usage within cygwin on windows.

This tool does not scan for all possible known public vulnerabilities, it only
scans for specific commonly vulnerable open source components.   A complete
list of currently supported library checkers can be found in [the checkers 
directory](https://github.com/intel/cve-bin-tool/tree/master/cve_bin_tool/checkers).

As the name implies, this tool is intended for use with binaries.  If you have
access to a known list of product names and versions, we do have a helper tool called [CSV2CVE](https://github.com/intel/cve-bin-tool/blob/master/CSV2CVE.md) that can be used to look up known vulnerabilities given a comma-delimited file.  See the [documentation for CSV2CVE for more details](https://github.com/intel/cve-bin-tool/blob/master/CSV2CVE.md).

Options:
--------

### -x, --extract

This option allows the CVE Binary Tool to extract compressed files into a temporary directory so the contents can be scanned.  If the quiet flag is not used, the list of extracted files will be printed.

### -s SKIPS, --skips SKIPS

This option allows one to skip (disable) a comma-separated list of checkers.  This can be useful for improving the performance of the tool when you have some prior knowledge about what checkers may apply to the binary you are scanning.  

### -r CHECKERS, --runs CHECKERS

This option allows one to enable a comma-separated list of checkers.

### -m, --multithread enable multithread

This options allows one to enable multithread mode, so that the scanner can run in parallel on many files at once. This can be used to improve performance, particularly if you are scanning a large directory or a compressed file with many files in it.

### -u {now,daily,never}, --update {now,daily,never}

This option controls the frequency of updates for the CVE data from the National Vulnerability Database.  By default, the tool checks the staleness of the data with every run, and if the data is more than one day old, it gets an update from NVD.  You may also choose to update the data `now` (in which case all cached data is deleted and a full new download is done) or `never` in which case the staleness check is not done and no update is requested.  The `now` and `never` modes can be combined to produce alternative update schedules if daily is not the desired one.

Output modes
------------

Although the examples in this section show results for a single library to make them shorter and easier to read, the tool was designed to be run on entire directories and will scan all files in a directory if one is supplied.

### -o OUTPUT_FILE, --output-file OUTPUT_FILE

This option allows you to specify the filename for the report, rather than having CVE Binary Tool generate it by itself.

### -f {csv,json,console}, --format {csv,json,console}

This option allows the CVE Binary Tool to produce a report in an alternate format. This is useful if you have other tools which only take a specific format. The default is `console` which pretty-prints the information.
1. `--format csv` - prints in csv (comma separated) format.
```
libgcrypt,1.6.0,CVE-2017-9526,MEDIUM
libgcrypt,1.6.0,CVE-2018-0495,MEDIUM
libgcrypt,1.6.0,CVE-2018-6829,HIGH
```
2. `--format json` - prints in json (javascript object notation) format.
```json
[
    {
        "package": "libgcrypt",
        "version": "1.6.0",
        "cve_number": "CVE-2017-9526",
        "severity": "MEDIUM"
    },
    {
        "package": "libgcrypt",
        "version": "1.6.0",
        "cve_number": "CVE-2018-0495",
        "severity": "MEDIUM"
    },
    {
        "package": "libgcrypt",
        "version": "1.6.0",
        "cve_number": "CVE-2018-6829",
        "severity": "HIGH"
    }
]
```
3. `--format console` - prints in nice tabular format.
```console
+=================================================================+
|   CVE Binary Tool Report Generated: 2020-04-29  10:04:06        |
+=================================================================+

+=================================================================+
|   MODULE NAME      |  VERSION  |    CVE NUMBER      | SEVERITY  |
+=================================================================+
| bzip2              | 1.0.2     | CVE-2005-0953      | LOW       |
+--------------------+-----------+--------------------+-----------+
| bzip2              | 1.0.2     | CVE-2005-1260      | MEDIUM    |
+--------------------+-----------+--------------------+-----------+
| bzip2              | 1.0.2     | CVE-2008-1372      | MEDIUM    |
+--------------------+-----------+--------------------+-----------+

```

### Output verbosity

As well as the modes above, there are two other output options to decrease or increase the number of messages printed:

1. Quiet mode (-q) suppresses all output but exits with an error number indicating the number of files with known CVEs.  This is intended for continuous integration and headless tests, while the other modes are all more human-friendly.
2. Log mode (-l log_level) prints logs of the specified log_level and above. The default log level is info. The logs can be suppressed by using quiet mode.

### Quiet Mode

As the name implies, quiet mode has no console output, and one must check the
return code to see if any issues were found.  The return value will be the number of files that have been found to have CVEs

Below is what it returns on bash when one file is found to have CVEs:

```console
terri@sandia:~/Code/cve-bin-tool$ cve-bin-tool -q ~/output_test_quiet/openssl 
terri@sandia:~/Code/cve-bin-tool$ echo $?
1
```

Note that errors are returned as negative numbers.  Any positive number
indicates that CVEs may be present in the code.  A good result here is 0.

### Logging modes

The logging modes provide additional fine-grained control for debug information.

Feedback & Contributions
------------------------

Bugs and feature requests can be made via [GitHub
issues](https://github.com/intel/cve-bin-tool).  Be aware that these issues are
not private, so take care when providing output to make sure you are not
disclosing security issues in other products.

Pull requests are also welcome via git.


Security Issues
---------------

Security issues with the tool itself can be reported to Intel's security
incident response team via
[https://intel.com/security](https://intel.com/security).

If in the course of using this tool you discover a security issue with someone
else's code, please disclose responsibly to the appropriate party.
