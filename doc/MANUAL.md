# CVE Binary Tool User Manual

- [CVE Binary Tool User Manual](#cve-binary-tool-user-manual)
  - [How it works](#how-it-works)
  - [Installing](#installing)
  - [Fixing Known Issues / What should I do if it finds something?](#fixing-known-issues--what-should-i-do-if-it-finds-something)
  - [Limitations](#limitations)
  - [Optional Arguments](#optional-arguments)
    - [-e EXCLUDE, --exclude EXCLUDE](#-e-exclude---exclude-exclude)
    - [-h, --help](#-h---help)
    - [-V, --version](#-v---version)
    - [--disable-version-check](#--disable-version-check)
    - [--disable-validation-check](#--disable-validation-check)
  - [CVE Data Download Arguments](#cve-data-download-arguments)
    - [-u {now,daily,never,latest}, --update {now,daily,never,latest}](#-u-nowdailyneverlatest---update-nowdailyneverlatest)
    - [-n {json,api}, --nvd {json,api}](#-n-jsonapi---nvd-jsonapi)
    - [--nvd-api-key NVD_API_KEY](#--nvd-api-key-nvd_api_key)
  - [Checkers Arguments](#checkers-arguments)
    - [-s SKIPS, --skips SKIPS](#-s-skips---skips-skips)
    - [-r CHECKERS, --runs CHECKERS](#-r-checkers---runs-checkers)
  - [Input Arguments](#input-arguments)
    - [directory (positional argument)](#directory-positional-argument)
    - [-i INPUT_FILE, --input-file INPUT_FILE](#-i-input_file---input-file-input_file)
    - [-L PACKAGE_LIST, --package-list PACKAGE_LIST](#-l-package_list---package-list-package_list)
    - [-C CONFIG, --config CONFIG](#-c-config---config-config)
      - [Yaml example file](#yaml-example-file)
      - [Toml example file](#toml-example-file)
  - [Output Arguments](#output-arguments)
    - [-o OUTPUT_FILE, --output-file OUTPUT_FILE](#-o-output_file---output-file-output_file)
    - [--html-theme HTML_THEME](#--html-theme-html_theme)
    - [-f {csv,json,console,html}, --format {csv,json,console,html}](#-f-csvjsonconsolehtml---format-csvjsonconsolehtml)
    - [-c CVSS, --cvss CVSS](#-c-cvss---cvss-cvss)
    - [-S {low,medium,high,critical}, --severity {low,medium,high,critical}](#-s-lowmediumhighcritical---severity-lowmediumhighcritical)
    - [--report](#--report)
    - [-A [<distro_name>-<distro_version_name>], --available-fix [<distro_name>-<distro_version_name>]](#-A-distro_name-distro_version_name---available-fix-distro_name-distro_version_name)
    - [-b [<distro_name>-<distro_version_name>], --backport-fix [<distro_name>-<distro_version_name>]](#-b-distro_name-distro_version_name---backport-fix-distro_name-distro_version_name)
    - [--affected-versions](#--affected-versions)
    - [--vex VEX_FILE](#--vex-vex_file)
    - [Output verbosity](#output-verbosity)
      - [Quiet Mode](#quiet-mode)
      - [Logging modes](#logging-modes)
  - [Merge Report Arguments](#merge-report-arguments)
    - [-a INTERMEDIATE_PATH, --append INTERMEDIATE_PATH](#-a-intermediate_path---append-intermediate_path)
    - [-t TAG, --tag TAG](#-t-tag---tag-tag)
    - [-m INTERMEDIATE_REPORTS, --merge INTERMEDIATE_REPORTS](#-m-intermediate_reports---merge-intermediate_reports)
    - [-F TAGS, --filter TAGS](#-f-tags---filter-tags)
  - [Deprecated Arguments](#deprecated-arguments)
    - [-x, --extract](#-x---extract)
  - [Feedback & Contributions](#feedback--contributions)
  - [Security Issues](#security-issues)

The CVE Binary Tool scans for a number of common, vulnerable open source
components like openssl, libpng, libxml2, expat etc. to let you know
if a given directory or binary file includes common libraries with
known vulnerabilities., known as CVEs(Common Vulnerabilities and Exposures).

Usage:
`cve-bin-tool`

You can also do `python -m cve_bin_tool.cli`
which is useful if you're trying the latest code from
[the cve-bin-tool github](https://github.com/intel/cve-bin-tool).

    optional arguments:
      -h, --help            show this help message and exit
      -e, --exclude         exclude path while scanning
      -V, --version         show program's version number and exit
      -x, --extract         autoextract compressed files
      --disable-version-check
                            skips checking for a new version
      --disable-validation-check
                            skips checking xml files against schema
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
      -L PACKAGE_LIST, --package-list PACKAGE_LIST
                        provide package list
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

For a quick overview of usage and how it works, you can also see [the readme file](README.md).

## How it works

This scanner looks at the strings found in binary files to see if they
match vulnerable versions of a small set of popular open source libraries.

It does not attempt to exploit issues or examine code in greater detail.
As such, it cannot tell if someone has backported fixes to an otherwise
vulnerable version, it merely provides a mapping between strings, versions, and
known CVEs.

A [list of currently available checkers](https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers)
can be found in the checkers directory or using `cve-bin-tool --help` command, as can the
[instructions on how to add a new checker](https://github.com/intel/cve-bin-tool/blob/main/cve_bin_tool/checkers/README.md).
Support for new checkers can be requested via
[GitHub issues](https://github.com/intel/cve-bin-tool/issues).
(Please note, you will need to be logged in to add a new issue.)

This tool gives a list of CVE numbers.  For those not familiar with the process,
these can be looked up using a number of different tools, such as the
[vulnerability search on the CVE Details website](https://www.cvedetails.com/vulnerability-search.php).
Each CVE field contains a short summary of the issue, a set of severity scores
that are combined to make a CVSS score, a list of products known to be affected, and
links to more information (which may include links to sample exploits as well as patches to fix the issue).

## Installing

`cve-bin-tool` can be installed via pip. If your `PATH` environment variable is
properly configured, installation will result in `cve-bin-tool` being accessible
globally. If not you can treat `cve-bin-tool` as `python -m cve_bin_tool.cli`.

```console
pip install -U cve-bin-tool
```

If you want the latest and greatest between releases you can grab from GitHub.

```console
pip install -U git+https://github.com/intel/cve-bin-tool
```

CVE Binary Tool relies on a few command line utilities which are usually present
on GNU/Linux systems but you may need to install.

- `file`
- `strings`
- `tar`
- `unzip`
- `rpm2cpio`
- `cpio`
- `ar`
- `cabextract`

On Windows, it requires

- `ar`
- `7z`
- `Expand`

Windows has `ar` and `Expand` installed in default, but `7z` in particular might need to be installed.
If you wan to run our test-suite or scan a zstd compressed file, We recommend installing this [7-zip-zstd](https://github.com/mcmilk/7-Zip-zstd)
fork of 7zip. We are currently using `7z` for extracting `jar`, `apk`, `msi`, `exe` and `rpm` files.

## Fixing Known Issues / What should I do if it finds something?

The most recommended way to fix a given CVE is to upgrade the package to a
non-vulnerable version.  Ideally, a CVE is only made public after a fix is
available, although this is not always the case.

If this is not possible for some reason, search for the CVE number to get
information on possible workarounds and patches that could be backported to
other versions.  Note that neither workarounds nor backported fixes can be
detected by this tool, so your binary will continue to show up as vulnerable
even though it may now be safely mitigated and result in a false positive.
To avoid this problem, we recommend classifying CVE as Mitigated as explained
in the Input section.

## Limitations

The last release of this tool to support python 2.7 is 0.3.1.  Please use
python 3.7+ for development and future versions.  Linux and Windows are
supported, as is usage within cygwin on windows.

This tool does not scan for all possible known public vulnerabilities, it only
scans for specific commonly vulnerable open source components.   A complete
list of currently supported library checkers can be found in [the checkers
directory](https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers).

As the name implies, this tool is intended for use with binaries. If you have
access to a known list of product names and versions, we do have an option `--input-file`
that can be used to look up known vulnerabilities given a CSV or JSON file.
See the detailed description of [`--input-file`](#-i-input_file---input-file-input_file) for more details.

## Optional Arguments

### -e EXCLUDE, --exclude EXCLUDE

This option allows one the skip a comma-separated lists of paths. This can be useful for excluding certain files and directories from the scan which will also decrease the scanning time.

### -h, --help

This option shows a help message and exits.

### -V, --version

This option shows program's version number and exits.

### --disable-version-check

This option skips checking for a new version of the program.

### --disable-validation-check

This option skips validating XML files (e.g. within an SBOM) against a schema.

## CVE Data Download Arguments

### -u {now,daily,never,latest}, --update {now,daily,never,latest}

This option controls the frequency of updates for the CVE data from the National Vulnerability Database.  By default, the tool checks the staleness of the data with every run, and if the data is more than one day old, it gets an update from NVD.  You may also choose to update the data `now` (in which case all cached data is deleted and a full new download is done) or `never` in which case the staleness check is not done and no update is requested.  The `now` and `never` modes can be combined to produce alternative update schedules if daily is not the desired one.

### -n {json,api}, --nvd {json,api}

This option selects how CVE data is downloaded from the National Vulnerability Database.  The default `api` option uses the NVD CVE Retrieval API. The results from this API are updated as quickly as the NVD website.  
A major benefit of using this NVD API is incremental updates which basically means you won't have to download the complete feed again in case you want the latest CVE entries from NVD. See the detailed guide on [incremental updates](how_to_guides/use_incremental_updates.html) for more details.

You may also choose to update the data using `json` option which uses the JSON feeds available on [this page](https://nvd.nist.gov/vuln/data-feeds). These per-year feeds are updated once per day.  This mode was the default for CVE Binary Tool prior to the 3.0 release.

### --nvd-api-key NVD_API_KEY

An NVD API key allows registered users to make a greater number of requests to the API.  At this time, the [NVD API documentation](https://nvd.nist.gov/developers)) says, "The public rate limit (without an API key) is 10 requests in a rolling 60 second window; the rate limit with an API key is 100 requests in a rolling 60 second window."

CVE Binary tool by default queries the NVD database once per day and caches the results to help alleviate load on the NVD servers.  Users who update more regularly or who are running the tool in shared environments (such as cloud providers or GitHub Actions) may find themselves hitting the rate limits despite those precautions and should obtain and use an NVD API key with CVE Binary Tool.

To get an API key, users should visit the [NVD API key request page](https://nvd.nist.gov/developers/request-an-api-key).

Related: [NVD API key announcement](https://nvd.nist.gov/general/news/API-Key-Announcement)

## Checkers Arguments

### -s SKIPS, --skips SKIPS

This option allows one to skip (disable) a comma-separated list of checkers.  This can be useful for improving the performance of the tool when you have some prior knowledge about what checkers may apply to the binary you are scanning.  

### -r CHECKERS, --runs CHECKERS

This option allows one to enable a comma-separated list of checkers.

## Input Arguments

### directory (positional argument)

Specify path to directory you want to scan.

### -i INPUT_FILE, --input-file INPUT_FILE

This option extends functionality of *csv2cve* for other formats like JSON and allow cve-bin-tool to accept some form of triage data and incorporate that into the output so that people could spend less time re-triaging.

You can provide either CSV or JSON file as input_file with vendor, product and version fields. You can also add optional fields like remarks, comments, cve_number, severity. Here's the detailed description and usecase of each fields:

1. **vendor, product, version** - To query locally stored CVE database and give you a list of CVEs that affect each vendor, product, version listed.
2. **remarks** - remarks help you categorized different CVEs into different categories like:
    - NewFound (1, n, N)
    - Unexplored (2, u, U)
    - Confirmed (3, c, C)
    - Mitigated, (4, m, M)
    - Ignored (5, i, I)

- All the characters denoted in parenthesis are aliases for that specific value. Output will be displayed in the same order as priority given to the remarks.

3. **comments** - You can write any comments you want to write in this field. This will be ignored in the console output but will be propagated as it is in CSV, JSON or HTML formats.
4. **severity** - This field allows you to adjust severity score of specific product or CVE. This can be useful in the case where CVE affects a portion of  the library that you aren't using currently but you don't want to ignore it completely. In that case, you can reduce severity for this CVE.
5. **cve_number** - This field give you fine grained control over output of specific CVE. You can change remarks, comments and severity for specific CVE instead of whole product.

You can also provide a Vulnerability Exchange (VEX) file which contains the reported vulnerabilities for components within a product. The supported format
is the [CycloneDX](https://cyclonedx.org/capabilities/vex/) VEX format which can be generated using the `--vex` option. A VEX file is identified with a file extension of .vex.
For the triage process, the **state** value in the analysis section of each CVE should have one of the following values:

```
"under_review" - this is the default state and should be used to indicate the vulnerability is to be reviewed
"in_triage" - this should be used to indicate that the vulnerability is being reviewed
"exploitable" - this should be used to indicate that the vulnerability is known to be exploitable
"not_affected" - this should be used to indicate that the vulnerability has been mitigated
```

The **detail** value in the analysis section can be used to provide comments related to the state

You can use `-i` or `--input-file` option to produce list of CVEs found in given vendor, product and version fields (Usage: `cve-bin-tool -i=test.csv`) or supplement extra triage data like remarks, comments etc. while scanning directory so that output will reflect this triage data and you can save time of re-triaging (Usage: `cve-bin-tool -i=test.csv /path/to/scan`).

Note that `--input-file`, unlike `cve-bin-tool directory` scan, will work on *any* product known in the National Vulnerability Database, not only those that have checkers written.

> Note: For backward compatibility, we still support `csv2cve` command for producing CVEs from csv but we recommend using new `--input-file` command instead.

For Example if input_file contains following data:

| vendor        | product       | version  | remarks   | comments                              | cve_number     | severity |
| ------------- | ------------- | -------- | --------- | ------------------------------------- | -------------- | -------- |
| libjpeg-turbo | libjpeg-turbo | 2.0.1    | 3         | High priority need to resolve fast    | CVE-2018-19664 | CRITICAL |
| libjpeg-turbo | libjpeg-turbo | 2.0.1    | 2         | Need to mitigate cves of this product |                | HIGH     |
| haxx          | curl          | 7.59.0   | 1         |                                       |                |          |
| haxx          | libcurl       | 7.59.0   |           |                                       |                |          |
| mit           | kerberos_5    | 5-1.15.1 | 3         |                                       |                |          |
| mit           | kerberos      | 1.15.1   |           |                                       |                |          |
| sun           | sunos         | 5.4      | 4         |                                       |                |          |
| ssh           | ssh2          | 2.0      | Mitigated |                                       |                |          |

You can test it using our [test input file](https://github.com/intel/cve-bin-tool/blob/main/test/json/test_triage.json) with following command:

```console
cve-bin-tool -i="test/json/test_triage.json"
```

The output will look like following:

    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                               CVE BINARY TOOL                                ║
    ╚══════════════════════════════════════════════════════════════════════════════╝

     • cve-bin-tool Report Generated: 2020-07-31  17:49:56
    ╭───────────────╮
    │ NewFound CVEs │
    ╰───────────────╯
    ┏━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
    ┃ Vendor ┃ Product ┃ Version ┃ CVE Number        ┃ Severity  ┃
    ┡━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
    │ haxx   │ curl    │ 7.59.0  │ CVE-2019-5443     │ HIGH      │
    │ haxx   │ curl    │ 7.59.0  │ CVE-2019-5481     │ CRITICAL  │
    └────────┴─────────┴─────────┴───────────────────┴───────────┘
    ╭─────────────────╮
    │ Unexplored CVEs │
    ╰─────────────────╯
    ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
    ┃ Vendor         ┃ Product        ┃ Version ┃ CVE Number      ┃ Severity  ┃
    ┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
    │ haxx           │ libcurl        │ 7.59.0  │ CVE-2018-14618  │ CRITICAL  │
    │ haxx           │ libcurl        │ 7.59.0  │ CVE-2018-16890  │ HIGH      │
    │ mit            │ kerberos       │ 1.15.1  │ CVE-2000-0547   │ MEDIUM    │
    │ libjpeg-turbo  │ libjpeg-turbo  │ 2.0.1   │ CVE-2018-20330  │ HIGH      │
    └────────────────┴────────────────┴─────────┴─────────────────┴───────────┘
    ╭────────────────╮
    │ Confirmed CVEs │
    ╰────────────────╯
    ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
    ┃ Vendor         ┃ Product        ┃ Version   ┃ CVE Number      ┃ Severity  ┃
    ┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
    │ mit            │ kerberos_5     │ 5-1.15.1  │ CVE-2018-5729   │ MEDIUM    │
    │ mit            │ kerberos_5     │ 5-1.15.1  │ CVE-2018-5730   │ LOW       │
    │ libjpeg-turbo  │ libjpeg-turbo  │ 2.0.1     │ CVE-2018-19664  │ CRITICAL  │
    └────────────────┴────────────────┴───────────┴─────────────────┴───────────┘
    ╭────────────────╮
    │ Mitigated CVEs │
    ╰────────────────╯
    ┏━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
    ┃ Vendor ┃ Product ┃ Version ┃ CVE Number     ┃ Severity ┃
    ┡━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
    │ ssh    │ ssh2    │ 2.0     │ CVE-1999-1029  │ HIGH     │
    │ ssh    │ ssh2    │ 2.0     │ CVE-1999-1231  │ MEDIUM   │
    │ sun    │ sunos   │ 5.4     │ CVE-1999-0008  │ HIGH     │
    └────────┴─────────┴─────────┴────────────────┴──────────┘

### -L PACKAGE_LIST, --package-list PACKAGE_LIST

This option runs a CVE scan on installed packages listed in a package list. It takes a python package list (requirements.txt) or a package list of packages of systems that has dpkg, pacman or rpm package manager as an input for the scan. This option is much faster and detects more CVEs than the default method of scanning binaries.

An example of the package list for Linux systems:

```
bash
unzip
firefox
sed
python3
```

> Note: The packages in the package list should be installed in the system before the scan. Run 
  - `pip install -r requirements.txt` to install python packages
  - `sudo apt-get install $(cat package-list)` for packages in a Debian based system
  - `sudo yum install $(cat package-list)`for packages in a CentOS/Fedora system
  - `sudo pacman -S $(cat package-list)` for packages in a system that uses pacman package manager (Arch Linux, Manjaro etc.)

> Note: Don't use invalid package names in the package list, as it may throw errors.

You can test it using our [test package list](https://github.com/intel/cve-bin-tool/blob/main/test/txt/test_ubuntu_list.txt) with following command:

```console
cve-bin-tool -L test/txt/test_ubuntu_list.txt
```
You can get a package list of all installed packages in   
  - a system using dpkg package manager by running `dpkg-query -W -f '${binary:Package}\n' > pkg-list` 
  - a system using pacman package manager by running `pacman -Qqe > pkg-list`
  - a system using rpm package manager by running `rpm -qa --queryformat '%{NAME}\n' > pkg-list` 
  
in the terminal and provide it as an input by running `cve-bin-tool -L pkg-list` for a full package scan.

### -C CONFIG, --config CONFIG

We currently have number of command line options and we understand that it won't be feasible to type all the option everytime you want to run a scan. You can use `--config` option to provide configuration file for the tool. You can still override options specified in config file with command line arguments. We support 2 most popular config file format:

1. TOML which is popular amongst Python developer and very similar to INI file. If you are not familiar with TOML checkout official [TOML documentation](https://toml.io/en/)
2. YAML which is popular amongst devops community and since many of our users are devops. We also support YAML as config file format. You can find out more about YAML at [yaml.org](https://yaml.org/)

You can see our sample TOML config file [here](https://github.com/intel/cve-bin-tool/blob/main/test/config/cve_bin_tool_config.toml) and sample YAML config file [here](https://github.com/intel/cve-bin-tool/blob/main/test/config/cve_bin_tool_config.yaml).

> You have to specify either a directory to scan and/or an input file containing vendor, product and version fields either in JSON or CSV format.


#### Yaml example file

```yaml
input:
  # Directory to scan
  directory: test/assets
  # To supplement triage data of previous scan or run standalone as csv2cve
  # Currently we only support csv and json file.
  input_file: test/csv/triage.csv

checker:
  # list of checkers you want to skip
  skips:
    - python
    - bzip2
  # list of checkers you want to run
  runs:
    - curl
    - binutils

output:
  # specify output verbosity from [debug, info, warning, error, critical]
  # verbosity will decreases as you go left to right (default: info)
  log_level: debug
  # if true then we don't display any output and
  # only exit-code with number of cves get returned
  # overwrites setting specified in log_level
  # Note: it's lowercase true or false
  quiet: false
  # specify one of an output format: [csv, json, html, console] (default: console)
  format: console
  # provide output filename (optional)
  # if not specified we will generate one according to output format specified
  output_file: ''
  # specify minimum CVE severity level to report from [low, medium, high, critical] (default: low)
  severity: low
  # specify minimum CVSS score to report from integer range 0 to 10 (default: 0)
  cvss: 0
other:
  # set true if you want to skip checking for newer version
  disable_version_check: false
  # update schedule for NVD database (default: daily)
  update: daily
  # set true if you want to autoextract archive files. (default: true)
  extract: true
```

#### Toml example file

```toml
[input]

# Directory to scan
directory = "test/assets"

# To supplement triage data of previous scan or run standalone as csv2cve
# Currently we only support csv and json file.
input_file = "test/csv/triage.csv"

[checker]

# list of checkers you want to skip
skips = ["python", "bzip2"]

# list of checkers you want to run
runs = ["curl", "binutils"]

[output]

# specify output verbosity from ["debug", "info", "warning", "error", "critical"]
# verbosity will decreases as you go left to right (default: "info")
log_level = "debug"

# if true then we don't display any output and
# only exit-code with number of cves get returned
# overwrites setting specified in log_level
# Note: it's lowercase true or false
quiet = false

# specify one of an output format: ["csv", "json", "html", "console"] (default: "console")
format = "console"

# provide output filename (optional)
# if not specified we will generate one according to output format specified
output_file = ""

# specify minimum CVE severity level to report from ["low", "medium", "high", "critical"] (default: "low")
severity = "low"

# specify minimum CVSS score to report from integer range 0 to 10 (default: 0)
cvss = 0

[other]
# set true if you want to skip checking for newer version
disable_version_check = false

# update schedule for NVD database (default: daily)
update = "daily"

# set true if you want to autoextract archive files. (default: true)
extract = true
```



## Output Arguments

Although the examples in this section show results for a single library to make them shorter and easier to read, the tool was designed to be run on entire directories and will scan all files in a directory if one is supplied.

### -o OUTPUT_FILE, --output-file OUTPUT_FILE

This option allows you to specify the filename for the report, rather than having CVE Binary Tool generate it by itself.

### --html-theme HTML_THEME

This option specifies the theme directory to be used in formatting the HTML report.

### -f {csv,json,console,html}, --format {csv,json,console,html}

This option allows the CVE Binary Tool to produce a report in an alternate format. This is useful if you have other tools which only take a specific format. The default is `console` which prints category wise beautiful tables of CVEs on terminal.

1. `--format csv` - write output file in csv (comma separated) format.

```csv
vendor,product,version,cve_number,severity,remarks,comments
haxx,curl,7.34.0,CVE-2014-0015,MEDIUM,Mitigated,
haxx,curl,7.34.0,CVE-2014-0138,MEDIUM,NewFound,
haxx,curl,7.34.0,CVE-2014-0139,MEDIUM,Unexplored,
```

2. `--format json` - write output file in json (javascript object notation) format.

```json
[
  {
    "vendor": "haxx",
    "product": "curl",
    "version": "7.34.0",
    "cve_number": "CVE-2014-0015",
    "severity": "MEDIUM",
    "remarks": "Mitigated",
    "comments": ""
  },
  {
    "vendor": "haxx",
    "product": "curl",
    "version": "7.34.0",
    "cve_number": "CVE-2014-0138",
    "severity": "MEDIUM",
    "remarks": "NewFound",
    "comments": ""
  },
]
```

3. `--format console` - prints in nice colored tabular format.

<figure>
  <img src="https://i.imgur.com/UwH6vA7.png"
    alt="
    cve-bin-tool: Report Generated: 2020-07-31  17:49:56
    1. NewFound CVEs:
    Vendor, Product, Version, CVE Number   , Severity
    haxx  , curl   , 7.34.0 , CVE-2014-0138, HIGH
    haxx  , curl   , 7.34.0 , CVE-2014-0139, CRITICAL
    haxx  , curl   , 7.34.0 , CVE-2014-0015, MEDIUM
    "
    style="width:100%;white-space:pre;">
  <figcaption>formated console output</figcaption>
</figure>

4. `--format html` - creates a report in html format according to the specified HTML theme.

5. `--format pdf` - creates a report in PDF format.

If you wish to use PDF support, you will need to install the `reportlab`
library separately.

If you intend to use PDF support when you install cve-bin-tool you can specify it and
report lab will be installed as part of the cve-bin-tool install:
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

### -c CVSS, --cvss CVSS

This option specifies the minimum CVSS score (as integer in range 0 to 10) of the CVE to report. The default value is 0 which results in all CVEs being reported.

### -S {low,medium,high,critical}, --severity {low,medium,high,critical}

This option specifies the minimum CVE severity to report. The default value is low which results in all CVEs being reported.

Note that this option is overridden by `--cvss` parameter if this is also specified. 

### --report

This option produces a report for all output formats even if there are 0 CVEs. By default CVE Binary tool doesn't produce an output when there are 0 CVEs.

### -A [<distro_name>-<distro_version_name>], --available-fix [<distro_name>-<distro_version_name>]

This option lists the available fixes of the package from Linux distribution if there are any.

The currently supported Linux distributions are:

```
debian-bullseye
debian-stretch
debian-buster
ubuntu-hirsute
ubuntu-groovy
ubuntu-focal
ubuntu-eoan
ubuntu-disco
ubuntu-cosmic
ubuntu-bionic
ubuntu-artful
ubuntu-zesty
ubuntu-yakkety
ubuntu-xenial
```


### -b [<distro_name>-<distro_version_name>], --backport-fix [<distro_name>-<distro_version_name>]

This option outputs the available backported fixes for the packages with CVEs if there are any.

By default CVE Binary tool checks for backported fixes according to the Linux distribution of the local machine. You can specify the distribution information explicitly in `<distro_name>-<distro_version_name>` fashion.

```console
cve-bin-tool <path-to-binary> --backport-fix ubuntu-focal
```

Currently supported options

```
debian-bullseye
debian-stretch
debian-buster
ubuntu-hirsute
ubuntu-groovy
ubuntu-focal
ubuntu-eoan
ubuntu-disco
ubuntu-cosmic
ubuntu-bionic
ubuntu-artful
ubuntu-zesty
ubuntu-yakkety
ubuntu-xenial
```

### --affected-versions

This options reports the versions of a product affected by a given CVE.

### --vex VEX_FILE

This option allows you to specify the filename for a Vulnerability Exchange (VEX) 
file which contains all the reported vulnerabilities detected by the scan. This file is typically
updated (outside of the CVE Binary tool) to record the results of a triage activity
and can be used as a file with `--input-file` parameter.

### Output verbosity

As well as the modes above, there are two other output options to decrease or increase the number of messages printed:

1. **Quiet mode (-q)** suppresses all output but exits with an error number indicating the number of files with known CVEs.  This is intended for continuous integration and headless tests, while the other modes are all more human-friendly.
2. **Log mode (-l log_level)** prints logs of the specified log_level and above. The default log level is info. The logs can be suppressed by using quiet mode.

#### Quiet Mode

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

#### Logging modes

The logging modes provide additional fine-grained control for debug information.

## Merge Report Arguments

Users may wish to create and combine multiple cve-bin-tool reports to track how vulnerability changes over time, how long it takes to fix issues, or other changes between different reports.  We have a number of options related to merging report data.  

### -a INTERMEDIATE_PATH, --append INTERMEDIATE_PATH

This option allows you to save the output in form of an intermediate report which you can later merge with other reports of the same format.  
See the detailed guide on [`intermediate reports`](how_to_guides/use_intermediate_reports.html) for more details.  

Intermediate report format

```json
{
    "metadata": {
        "timestamp": "2021-06-17.00-00-30",
        "tag": "backend",
        "scanned_dir": "/home/path/",
        "products_with_cve": 139,
        "products_without_cve": 2,
        "total_files": 49
    },
    "report": [
        {
            "vendor": "gnu",
            "product": "gcc",
            "version": "9.0.1",
            "cve_number": "CVE-2019-15847",
            "severity": "HIGH",
            "score": "7.5",
            "cvss_version": "3",
            "paths": "/home/path/glib.tar.gz,/home/path/gcc.tar.gz",
            "remarks": "NewFound",
            "comments": ""
        },
    ]
}
```

### -t TAG, --tag TAG

This option allows you to save a tag inside the metadata of intermediate reports. By default the value is empty `""`

### -m INTERMEDIATE_REPORTS, --merge INTERMEDIATE_REPORTS

This option allows you to merge intermediate reports created using `-a` or `--append`. The output from the merged report produces a report on the console. But you can also use it along with `-f --format` and `-o --output-file` to produce output in other formats. It takes a list of comma-separated filepaths.

### -F TAGS, --filter TAGS

This allows you to filter out intermediate reports based on the tag. This can be useful while merging multiple intermediate reports from a single path. See detailed guide on [`filter intermediate reports`](how_to_guides/filter_intermediate_reports.md) for more information.

## Deprecated Arguments

### -x, --extract

This option allows the CVE Binary Tool to extract compressed files into a temporary directory
so the contents can be scanned.  If the quiet flag is not used, the list of extracted files
will be printed.

CVE Binary Tool by default auto-extract all compressed files inside the directory path. You can always exclude certain paths by using `-e --exclude`

## Feedback & Contributions

Bugs and feature requests can be made via [GitHub issues](https://github.com/intel/cve-bin-tool/issues).
Be aware that these issues are not private, so take care when providing output to make sure
you are not disclosing security issues in other products.

Pull requests are also welcome via git.

## Security Issues

Security issues with the tool itself can be reported to Intel's security incident response team via [https://intel.com/security](https://intel.com/security).

If in the course of using this tool you discover a security issue with someone
else's code, please disclose responsibly to the appropriate party.
