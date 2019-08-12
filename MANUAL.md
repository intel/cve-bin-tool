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
  -v, --verbose         details on found issues as script runs
  -q, --quiet           suppress output
  -l {debug,info,warning,error,critical}, --log {debug,info,warning,error,critical}
                        log level
```
Other options:
```
  -h, --help            show help message and exit
  -x, --extract         autoextract compressed files
  -s SKIPS, --skips SKIPS
                        comma-separated list of checkers to disable
  -m, --multithread     enable multithread
  -u {now,daily,never}, --update {now,daily,never}
                        update schedule for NVD database. Default is daily.
```

Available checkers: `curl, expat, icu, kerberos, libcurl, libgcrypt, libjpeg,
libnss, libtiff, node, openssl, png, sqlite, systemd, xerces, xml2, zlib
`

For a quick overview of usage and how it works, you can also see [the readme file](README.md).


Table of Contents
-----------------
- [CVE checker for binary code User Manual](#CVE-checker-for-binary-code-User-Manual)
  - [Table of Contents](#Table-of-Contents)
  - [How it works](#How-it-works)
  - [Installing](#Installing)
  - [Fixing Known Issues / What should I do if it finds something?](#Fixing-Known-Issues--What-should-I-do-if-it-finds-something)
  - [Limitations](#Limitations)
  - [Options:](#Options)
    - [-x, --extract](#x---extract)
    - [-s SKIPS, --skips SKIPS](#s-SKIPS---skips-SKIPS)
    - [-m, --multithread enable multithread](#m---multithread-enable-multithread)
    - [-u {now,daily,never}, --update {now,daily,never}](#u-nowdailynever---update-nowdailynever)
  - [Output modes](#Output-modes)
      - [Default Mode](#Default-Mode)
    - [Verbose Mode](#Verbose-Mode)
    - [Quiet Mode](#Quiet-Mode)
    - [Logging modes](#Logging-modes)
  - [Feedback & Contributions](#Feedback--Contributions)
  - [Security Issues](#Security-Issues)

How it works
------------
This scanner looks at the strings found in binary files to see if they
match vulnerable versions of a small set of popular open source libraries.

It does not attempt to exploit issues or examine code in greater detail.
As such, it cannot tell if someone has backported fixes to an otherwise
vulnerable version, it merely provides a mapping between strings, versions, and
known CVEs.

A [list of currently available checkers](checkers/) can be found in the checkers
directory, as can the [instructions on how to add a new
checker](cve_bin_tool/checkers/README.md).  Support for new checkers can be requested
via [GitHub
issues](https://github.com/intel/cve-bin-tool/issues).
(Please note, you will need to be logged in to add a new issue.)


This tool gives a list of CVE numbers.  For those not familiar with the process, these can be looked up using a number of different tools, such as the [vulnerability search on the CVE Details website](https://www.cvedetails.com/vulnerability-search.php).  Each CVE filed contains a short summary of the issue (also printed when you use the -v flag in this tool), a set of severity scores that are combined to make a CVSS score, a list of products known to be affected, and links to more information (which may include links to sample exploits as well as patches to fix the issue).

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

When running this script, Python 3 is preferred over Python 2.7, as python 2.7 support will be ending soon. Linux and Windows are supported, as is usage within cygwin on windows.

This tool does not scan for all possible known public vulnerabilities, it only
scans for specific commonly vulnerable open source components.   A complete
list of currently supported library checkers can be found in [the checkers 
directory](https://github.com/intel/cve-bin-tool/tree/master/checkers).

As the name implies, this tool is intended for use with binaries.  If you have
access to a known list of package names and versions, we do have a helper tool called [CSV2CVE](https://github.com/intel/cve-bin-tool/blob/master/CSV2CVE.md) that can be used to look up known vulnerabilities given a comma-delimited file.  See the [documentation for CSV2CVE for more details](https://github.com/intel/cve-bin-tool/blob/master/CSV2CVE.md).

Options:
--------

### -x, --extract

This option allows the CVE Binary Tool to extract compressed files into a temporary directory so the contents can be scanned.  If the quiet flag is not used, the list of extracted files will be printed.

### -s SKIPS, --skips SKIPS

This option allows one to skip (disable) a comma-separated list of checkers.  This can be useful for improving the performance of the tool when you have some prior knowledge about what checkers may apply to the binary you are scanning.  

###   -m, --multithread     enable multithread

This options allows one to enable multithread mode, so that the scanner can run in parallel on many files at once. This can be used to improve performance, particularly if you are scanning a large directory or a compressed file with many files in it.

### -u {now,daily,never}, --update {now,daily,never}

This option controls the frequency of updates for the CVE data from the National Vulnerability Database.  By default, the tool checks the staleness of the data with every run, and if the data is more than one day old, it gets an update from NVD.  You may also choose to update the data `now` (in which case all cached data is deleted and a full new download is done) or `never` in which case the staleness check is not done and no update is requested.  The `now` and `never` modes can be combined to produce alternative update schedules if daily is not the desired one.

Output modes
------------

The tool has several different output modes, from most information to least as follows:

1. Verbose mode (-v) Prints scan results as they're found (while crawling a directory)
2. Regular mode (no flag) prints only the final summary of findings
3. Quiet mode (-q) suppresses all output but exits with an error number indicating the number of files with known CVEs.  This is intended for continuous integration and headless tests, while the other modes are all more human-friendly.

Although the examples in this section show results for a single library to make them shorter and easier to read, the tool was designed to be run on entire directories and will scan all files in a directory if one is supplied.

#### Default Mode

The default mode for the cve-bin-tool prints only a final summary of results,
without CVE descriptions or information while the scan is progressing. It
outputs a CSV with the results to stdout. In the form of `package name, version,
CVE number, CVE severity`. Below is an example of it being run on our expat test file:

```console
(venv3.6) terri@sandia:~/Code/cve-bin-tool$ python -m cve_bin_tool.cli test/binaries/test-expat-2.0.1.out 
Updating CVE data. This will take a few minutes.
Last Update: 2019-08-09
Local database has been updated in the past 24h.
New data not downloaded.  Use "-u now" to force an update

Overall CVE summary: 
There are 1 files with known CVEs detected
Known CVEs in expat 2.0.1:
expat,2.0.1,CVE-2012-6702,MEDIUM
expat,2.0.1,CVE-2016-0718,CRITICAL
expat,2.0.1,CVE-2016-5300,HIGH
expat,2.0.1,CVE-2018-20843,HIGH
expat,2.0.1,CVE-2012-0876,MEDIUM
expat,2.0.1,CVE-2012-1147,MEDIUM
expat,2.0.1,CVE-2012-1148,MEDIUM
expat,2.0.1,CVE-2013-0340,MEDIUM
```

This mode is meant to give the user enough information that they can
investigate further.

### Verbose Mode
The verbose mode is another human-friendly mode.  Unlike default mode, it
prints results per file as they're found, as well as printing the final
summary, so you can see its progress as it traverses directories.  

```console
(venv3.6) terri@sandia:~/Code/cve-bin-tool$ python -m cve_bin_tool.cli -v -x ~/output_test_verbose/
Updating CVE data. This will take a few minutes.
Last Update: 2019-08-09
Local database has been updated in the past 24h.
New data not downloaded.  Use "-u now" to force an update
Checkers: curl, expat, icu, kerberos, libcurl, libgcrypt, libjpeg, libnss, libtiff, node, openssl, png, sqlite, systemd, xerces, xml2, zlib
./usr/bin/sqlite3
./usr/lib/libsqlite3.so.0
./usr/lib/libsqlite3.so.0.8.6
./usr/share/doc/sqlite-3.1.2
./usr/share/doc/sqlite-3.1.2/README
./usr/share/man/man1/sqlite3.1.gz
780 blocks
/tmp/cve-bin-tool-2qyr5nh7/sqlite-3.1.2-2.99_2.el4.at.i386.rpm.extracted/usr/lib/libsqlite3.so.0.8.6 is sqlite 3.1.2
Known CVEs in version 3.1.2
CVE-2018-20346, CVE-2018-20506
/tmp/cve-bin-tool-2qyr5nh7/sqlite-3.1.2-2.99_2.el4.at.i386.rpm.extracted/usr/bin/sqlite3 is sqlite 3.UNKNOWN
./usr/bin/curl
./usr/share/doc/curl
./usr/share/doc/curl/BUGS
./usr/share/doc/curl/CHANGES
./usr/share/doc/curl/COPYING
./usr/share/doc/curl/FAQ
./usr/share/doc/curl/FEATURES
./usr/share/doc/curl/MANUAL
./usr/share/doc/curl/README
./usr/share/doc/curl/RESOURCES
./usr/share/doc/curl/TODO
./usr/share/doc/curl/TheArtOfHttpScripting
./usr/share/man/man1/curl.1.gz
1092 blocks
/tmp/cve-bin-tool-2qyr5nh7/curl-7.32.0-3.fc20.x86_64.rpm.extracted/usr/bin/curl is curl 7.32.0
Known CVEs in version 7.32.0
CVE-2018-1000007, CVE-2014-8150, CVE-2017-7407, CVE-2016-9586, CVE-2016-8615, CVE-2016-8617, CVE-2016-8618, CVE-2016-8624, CVE-2016-5419, CVE-2016-5420, CVE-2015-3153, CVE-2014-3613, CVE-2014-0139, CVE-2016-8619, CVE-2017-1000254, CVE-2016-8616, CVE-2015-3148, CVE-2015-3143, CVE-2014-0015, CVE-2016-8623, CVE-2016-0755, CVE-2014-0138, CVE-2016-7167, CVE-2016-4802, CVE-2016-8625, CVE-2016-8621, CVE-2018-1000120, CVE-2018-16842, CVE-2017-1000100, CVE-2018-14618, CVE-2014-3707, CVE-2013-4545, CVE-2019-5436, CVE-2016-7141, CVE-2018-1000301, CVE-2018-1000122, CVE-2017-1000257, CVE-2016-0754, CVE-2018-1000121, CVE-2017-8817, CVE-2016-3739, CVE-2013-6422, CVE-2016-8622, CVE-2014-2522, CVE-2014-1263, CVE-2016-9952, CVE-2016-9953, CVE-2015-3145, CVE-2014-8151, CVE-2014-3620, CVE-2016-5421

Overall CVE summary: 
There are 2 files with known CVEs detected
Known CVEs in sqlite 3.1.2, sqlite 3.UNKNOWN, curl 7.32.0:
sqlite,3.1.2,CVE-2018-20346,HIGH
sqlite,3.1.2,CVE-2018-20506,HIGH
... (Curl results omitted to save space)
```

### Quiet Mode

As the name implies, quiet mode has no console output, and one must check the
return code to see if any issues were found.  The return value will be the number of files that have been found to have CVEs

Below is what it returns on bash when one file is found to have CVEs:

```console
terri@sandia:~/Code/cve-bin-tool$ cve-bin-tool -q ~/output_test_quiet/openssl 
terri@sandia:~/Code/cve-bin-tool$ echo $?
1
```

Note that errors are returned as negative numbers.

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
