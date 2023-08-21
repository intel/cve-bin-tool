# Adding a new checker to the cve-bin-tool

- [Adding a new checker to the cve-bin-tool](#adding-a-new-checker-to-the-cve-bin-tool)
  - [Requirements](#requirements)
  - [Hints for finding the right data to use](#hints-for-finding-the-right-data-to-use)
    - [Finding binary files to use](#finding-binary-files-to-use)
    - [Finding a version pattern](#finding-a-version-pattern)
    - [Multi-line version patterns](#multi-line-version-patterns)
    - [Avoiding false positives (beware the X.X.X version pattern!)](#avoiding-false-positives-beware-the-xxx-version-pattern)
    - [Finding FILENAME_PATTERNS](#finding-filename_patterns)
    - [Choosing contains patterns to detect the library](#choosing-contains-patterns-to-detect-the-library)
    - [Quickstart for finding patterns](#quickstart-for-finding-patterns)
    - [Finding Vendor Product pairs](#finding-vendor-product-pairs)
  - [Helper-Script](#helper-script)
  - [Adding tests](#adding-tests)
  - [Running tests](#running-tests)
  - [How it works](#how-it-works)
  - [Updating checker table](#updating-checker-table)
  - [Pull Request Template](#pull-request-template)

## Requirements

In order to add a new checker to the CVE-bin-tool, one must provide a checker
file.  See any checker in the `checkers/` directory as an example.

Currently, a checker must provide one class which inherits Checker class of
the checkers module. class name of the checker must be same as filename of the
checker with `Checker` suffix at the end. Ex: if you are creating a checker for
`curl` binary then filename of checker should be `curl.py` and class definition
should be:

```python
from cve_bin_tool.checkers import Checker

class CurlChecker(Checker):
```

Every checker may contain following 5 class attributes specific to product(ex: curl)
you are making checker for:

1. CONTAINS_PATTERNS - list of commonly found strings in the binary of the product
2. FILENAME_PATTERNS - list of different filename for the product
3. VERSION_PATTERNS - list of version patterns found in binary of the product.
4. VENDOR_PRODUCT - list of vendor product pairs for the product as they appear in
NVD.
5. IGNORE_PATTERNS (optional) - list of patterns that could cause false positives (e.g. error messages that mention specific product/versions)

`CONTAINS_PATTERN`, `FILENAME_PATTERNS` and `VERSION_PATTERNS` supports regex to cover
wide range of use cases.

Once the checker is added, its name should also be added to `__init__.py` (so
that `from modules import *` will find it).

## Hints for finding the right data to use

### Finding binary files to use

You can use any binary freely available on the Internet to build your checker.   We typically build checkers for open source libraries because there is good data available for those; if building a checker for something that is not open source please be aware of licensing restrictions.  Most people start this process with a binary they already want to detect, but sometimes folk see a request for a checker and might need to find the software first.

Typical places to get binaries:

- Searching the project website for pre-compiled release files
- Packages done up for Linux distributions such as Fedora, Debian, and OpenSUSE
- Packages prepared for other operating systems

Here's a worked example for Mozilla Firefox:

For Mozilla Firefox, I would start with Linux distributions that have pre-packaged versions, because I know they exist and that people will likely want to detect these particular packages if they're scanning full systems.  (You can do some research with a search engine if you don't happen to know the software being requested.)  You can find Linux packages using a search engine or by checking their websites, but as it happens the folk writing existing tests have left you some hints:

Each test we have includes the link where the test writer got the binary they used, so there's a big list here in each file:

- <https://github.com/intel/cve-bin-tool/tree/main/test/test_data>

In general, the most recently updated tests are going to have the links that are easiest to work with -- it's the norm for software packages to be replaced with newer versions (e.g. to address security vulnerabilities!) and sometimes projects just rearrange their websites (although honestly, not that often).  We store local copies of test data so we don't have to update these all the time, but that means that some of those old URIs may just not work, so it's best to choose a file that's been updated relatively recently so you don't get sent down a rabbit hole of "where the files used to be."

To give you a worked example for this checker, let's look at the most recently merged test data for the `file` checker:

- <https://github.com/intel/cve-bin-tool/blob/main/test/test_data/file.py>

You can see that the author gave us a pile of different tests from different locations:

- <http://rpmfind.net/> has a bunch of different Linux distributions represented.  These particular ones point at OpenSUSE packages
- <http://ftp.fr.debian.org/> is a French Debian mirror.
- <https://downloads.openwrt.org/> is software included as part of openWRT (a distro targeted at embedded devices)
(I know these off the top of my head, but if you don't you can definitely search or go the main page of each site to help figure it out)

It's probably not common to have Firefox on an embedded device, but both OpenSUSE and Debian should have versions, so let's look at those two:

Look at the Debian link again:

- <http://ftp.fr.debian.org/debian/pool/main/f/file/>

It looks like they sort their packages alphabetically, and the last bit referred to the `file` package we were looking for in the test.  What happens if you go up a level either using the `../` link provided at the top of that page, or just by truncating the URI?

- <http://ftp.fr.debian.org/debian/pool/main/f/>

How convenient, that gives you the list of packages that start with f.  You should be able to find Firefox in there.  Incidentally, if you happen to do more research, there's also a Debian package search engine.  But often just walking the directory tree on the mirrors is faster.

<https://www.rpmfind.net/> is even easier to use: if you got to their main page, they have a package search box, so you can type in "Firefox" and get a huge list of packages:

<https://www.rpmfind.net/linux/rpm2html/search.php?query=firefox&submit=Search>+...

That should give you a couple of different binary versions of Firefox to run through the helper script program and use for the required tests. If you ever get stuck on this step, you can always [ask for help in the issue tracker](https://github.com/intel/cve-bin-tool/issues).

### Finding a version pattern

The VERSION_PATTERNS contains strings which will be used as a signature for
determining the version of the product that is present in the system. You should
keep in mind that these strings should be consistent across all versions of the
binary and in as many software distributions as possible.

You can get a basic idea of the pattern from looking at the project's documentation/website
or use [cvedetails](https://www.cvedetails.com/) since it catalogs vulnerable versions and
thus has version lists. Once you know what the version numbers look like, you'll need to
find them in the code or the binary itself to make sure you've got a findable pattern.

A few ways to do it:

- The CVE Binary tool basically works by running the command line utility `strings` on a file,
  so if you have a local copy of the library, you can run `strings $libraryname` and see what
  comes out.  try `strings $libraryname | grep $version` and see what you find, and if you
  don't find it that way `strings $libraryname | less` and page through (maybe run a filter
  in there so it's only strings over a certain size?)

- If you don't have a copy, browse through the source to find the version string. It's usually
  helpfully named something like 'version' so a quick grep/search often will turn it up, and
  if you know the latest version number (usually proudly mentioned in the latest news post
  or similar) you can grep for that and then look at the history to see what valid patterns
  look like.

### Multi-line version patterns

In Windows, a new line is denoted using "\r\n" and in Linux it's "\n".

For example, if the version string looks like this:

```
  <artifactId>commons-compress</artifactId>
  <version>1.16.1</version>
```

Then a good regex signature for this will be `r"<artifactId>commons-compress</artifactId>\r?\n  <version>([0-9]+\.[0-9]+(\.[0-9]+)?)</version>"`. And in case of the mapping tests, the `version_strings` parameter doesn't support regex strings, so just use "\r\n" to indicate a new line.

### Avoiding false positives (beware the X.X.X version pattern!)

It can be very tempting to have a version pattern that matches `X.X.X` where `X` is a number
(or in regex form: `r"[0-9]+\.[0-9]+\.[0-9]+"`).  But beware! There are lots of other
libraries potentially compiled in to your binary that will match `X.X.X`.  The ones you're
most likely going to see are gcc and glibc, the standard c library.

For an example, here's a list of some of the "interesting" version-like strings from one
of our binary test files:

```
~/Code/cve-bin-tool$ strings test/assets/test-curl-7.34.0.out
This program is designed to test the cve-bin-tool checker.
It outputs a few strings normally associated with libcurl 7.34.0.
They appear below this line.
------------------
An unknown option was passed in to libcurl
CLIENT libcurl 7.34.0
GCC: (x86_64, Built by MinGW-W64 project) 8.1.0
```

As you can see, there's a lot of things that will match `X.X.X`:

- libcurl is version 7.34.0
- gcc is version 8.1.0

So you want something that makes the version string a little more precise to the
product you're looking for.  For example, if we were *intentionally* looking for
libcurl (as in, writing a libcurl checker), we could use the string `curl` or
`libcurl` as a prefix and get a regex that would tell us about libcurl without
also telling us the GCC version.

So a good regex signature for libcurl might be `r"curl[ -/]([678]+\.[0-9]+\.[0-9]+)"`

The whole point of the CVE Binary Tool is to detect libraries that you might not
know are there, so we'd expect it often to be used on binaries that have a lot
of libraries compiled into them.  Finding a regex that detects only what you
care about even in the face of a lot of similar strings is essential for us to
avoid false positives.

It's also worth noting that sometimes there just aren't great version strings
available: sometimes `X.X.X` is all you can find.  If you get stuck at this
point, please make a note of it in the
[New Checker](https://github.com/intel/cve-bin-tool/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+%22new+checker%22)
issue if there is one. (You can make a new one and note it there if there isn't.)
That helps other contributors know that that particular checker is going to be
hard to do.  Once you've done that, you can abandon the checker and find something
easier to work on, or you can try to think outside the box to find another way
to detect the version.  One example is how we did it for the
[sqlite3 get_version_map() function](https://github.com/intel/cve-bin-tool/blob/main/cve_bin_tool/checkers/sqlite.py#L104)
where the checker uses version hashes from the website that are *also* stored
as strings in the binary.

### Finding FILENAME_PATTERNS

The FILENAME_PATTERNS contains the names of the files in the binary where the above
signatures were found. If there are more than one place where the version strings are
found, please make sure that you add all the filenames.

### Choosing contains patterns to detect the library

contains patterns are the string pattern that you commonly found in the binary of the
product you are looking for. You want a signature that hasn't changed in a large
number of versions so you'll detect the library as long as possible (and if you
notice that it did change before some version date, you can always add more
strings to improve the coverage).  If you have a copy of the library you can
run `strings $libraryname` to find some candidate strings that look good,
then you should look at their source repository to see when those strings
were added and if they were changed.  (there's a 'history' button on github
for this, or other tools for other repositories). `CONTAINS_PATTERNS` field supports
regex pattern so you can use creative signature which remain same for number of
versions.
> Note: We by default include VERSION_PATTERNS as a valid CONTAINS_PATTERNS

You can find these by-

```console
strings (path of the binary) | grep -i (product_name)
```

### Quickstart for finding patterns

What often helps is trying to find an `.rpm` (or more than one) or a package
which contains the product you're looking for.

Searching on <https://pkgs.org> is a good place to start.

For this example we'll be using `libvorbis`: <https://pkgs.org/search/?q=libvorbis>

In the below example we picked fedora 33's package for version 1.3.7 of
libvorbis. We can extract the `.rpm` file using a combination of
[rpm2cpio and cpio](https://www.cyberciti.biz/tips/how-to-extract-an-rpm-package-without-installing-it.html)
or using [rpmfile](https://pypi.org/project/rpmfile/). Sometimes you'll have
packages which come in `.deb` or .`tar` files.

- `.deb` files can be extracted with `ar x somefile.deb && tar xvf data.tar.xz`

- `.tar` files can be extracted using `tar`

```console
$ curl -sfL 'https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/33/Everything/x86_64/os/Packages/l/libvorbis-1.3.7-2.fc33.x86_64.rpm' | rpmfile -xv -
/tmp/tmp.U3wkntEqtD/usr/lib/.build-id/02/980384bc359497f0121fc74974e465ba7e29aa
/tmp/tmp.U3wkntEqtD/usr/lib/.build-id/1c/ff0ed918467a6224a5108793bf779e61486151
/tmp/tmp.U3wkntEqtD/usr/lib/.build-id/75/8407ea857c63ae42c4d9959ad252de6fb9bcca
/tmp/tmp.U3wkntEqtD/usr/lib64/libvorbis.so.0
/tmp/tmp.U3wkntEqtD/usr/lib64/libvorbis.so.0.4.9
/tmp/tmp.U3wkntEqtD/usr/lib64/libvorbisenc.so.2
/tmp/tmp.U3wkntEqtD/usr/lib64/libvorbisenc.so.2.0.12
/tmp/tmp.U3wkntEqtD/usr/lib64/libvorbisfile.so.3
/tmp/tmp.U3wkntEqtD/usr/lib64/libvorbisfile.so.3.3.8
/tmp/tmp.U3wkntEqtD/usr/share/doc/libvorbis/AUTHORS
/tmp/tmp.U3wkntEqtD/usr/share/licenses/libvorbis/COPYING
```

Then look for which files you downloaded are binaries or libraries. We can use
the `file` command combined with the `find` command for this. The `find`
command will list every file in the directory we provide to it (`.` in this
case) and execute any program we want using that filename. In this case we want
to run the `file` command on each file we get from `find`.

We want to filter the output using `grep` to show us only executables (programs
you run) and shared objects (libraries programs use) using
`-E 'executable,|shared object,'` which is a regex which says to show lines that
`find` output if they have either `executable,` or `shared object,` in them.

The final `tee` command in combination with `sed` is creating a new file called
`executables.txt` which has all the filenames in it. It does this by only
writing what comes before the `:` to the file that was in the output of the
`grep` command which looked for executables.

```console
$ find . -exec file {} \; | grep -E 'executable,|shared object,' | tee >(sed -e 's/:.*//g' > executables.txt)
./usr/lib64/libvorbisfile.so.3.3.8: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=1cff0ed918467a6224a5108793bf779e61486151, stripped
./usr/lib64/libvorbisenc.so.2.0.12: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=02980384bc359497f0121fc74974e465ba7e29aa, stripped
./usr/lib64/libvorbis.so.0.4.9: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=758407ea857c63ae42c4d9959ad252de6fb9bcca, stripped
```

You'll want to run strings on those binaries and do a case insensitive search
for the package name using `grep -i`.

```console
$ strings $(cat executables.txt) | sort | uniq | grep -i libvorbis
3?Xiph.Org libVorbis 1.3.7
libvorbisenc.so.2
libvorbisenc.so.2.0.12-1.3.7-2.fc33.x86_64.debug
libvorbisfile.so.3
libvorbisfile.so.3.3.8-1.3.7-2.fc33.x86_64.debug
libvorbis.so.0
libvorbis.so.0.4.9-1.3.7-2.fc33.x86_64.debug
Xiph.Org libVorbis I 20200704 (Reducing Environment)
```

You also might want to look for the version number. In this case it's `1.3.7`.

```console
$ strings $(cat executables.txt) | sort | uniq | grep -i 1.3.7
3?Xiph.Org libVorbis 1.3.7
libvorbisenc.so.2.0.12-1.3.7-2.fc33.x86_64.debug
libvorbisfile.so.3.3.8-1.3.7-2.fc33.x86_64.debug
libvorbis.so.0.4.9-1.3.7-2.fc33.x86_64.debug
```

In this case the most interesting line in the output of the above two commands
is `3?Xiph.Org libVorbis 1.3.7`. We can probably use this to create a regex for
`VERSION_PATTERNS`.

That regex might look like this: `3\?Xiph.Org libVorbis ([0-9]+\.[0-9]+\.[0-9]+)`

> If you can't get a signature match using just regex you may end up needing to
> overwrite the
> [`get_version()`](https://github.com/intel/cve-bin-tool/blob/main/cve_bin_tool/checkers/__init__.py#L120-L132)
> method for the checker, but that should be a last resort if you can't find a
> regex that works for `VERSION_PATTERNS`.
>
> A note about this example:
> In the case of libvorbis the versions containing
> [CVEs](https://www.cvedetails.com/product/11738/Libvorbis-Libvorbis.html?vendor_id=6970)
> are 1.2.0 and below. The `.rpm` we used for this example was from version
> 1.3.7. While this was a nice example for how one might find a signature, it
> in the end is not all the work that is needed to create a checker for
> libvorbis. We need to make sure that any checker we develop has a
> `get_version()` function which works for versions of the software which have
> CVEs. If not overridden in a subclass the Checker base class implements a
> `get_version()` method which will use regex to determine the version (as
> described above). In the case of libvorbis a custom `get_version()` function
> is likely needed, this is because the signature we found is not in the 1.2.0
> version, where the CVE is found.

### Finding Vendor Product pairs

Every checker class must contain the vendor and product name pair(s)
as they appear in NVD. The best way to do this is to search the cached sqlite
database of the NVD using a CVE you want to know the vendor product pair(s) for.

```console
$ sqlite3 ~/.cache/cve-bin-tool/cve.db \
    "SELECT vendor, product FROM cve_range WHERE CVE_Number='CVE-2016-0718';" \
    | sed -e 's/|/, /g' -e 's/^/VPkg\: /'
VPkg: apple, mac_os_x
VPkg: canonical, ubuntu_linux
VPkg: debian, debian_linux
VPkg: libexpat_project, libexpat
VPkg: mozilla, firefox
VPkg: opensuse, leap
VPkg: suse, linux_enterprise_debuginfo
```

`VENDOR_PRODUCT` attribute should have list of tuples of vendor product pair
found in the listings. Some of the listings will be with regards to products
that include this product. For our example all listings except
`libexpat_project, libexpat` merely include the target product (`libexpat` for
the example SQL query).

## Helper-Script

Helper-Script is a tool that takes a *package*(i.e. busybox_1.30.1-4ubuntu9_amd64.deb) as input and returns:

> 1. `CONTAINS_PATTERNS` - list of commonly found strings in the binary of the product
> 2. `FILENAME_PATTERNS` - list of different filename for the product
> 3. `VERSION_PATTERNS` - list of version patterns found in binary of the product.
> 4. `VENDOR_PRODUCT` - list of vendor product pairs for the product as they appear in NVD.

Helper-Script can also take multiple packages and `PRODUCT_NAME`(required) as input and return
common strings for `CONTAINS_PATTERNS`.

Usage: `python -m cve_bin_tool.helper_script`

```
positional arguments:
  filenames             files to scan

optional arguments:
  -h, --help            show this help message and exit
  -p PRODUCT_NAME, --product PRODUCT_NAME
                        provide product-name that would be searched
  -v VERSION_NUMBER, --version VERSION_NUMBER
                        provide version that would be searched
  -l {debug,info,warning,error,critical}, --log {debug,info,warning,error,critical}
                        log level (default: warning)
  --string-length STRING_LENGTH
                        changes the output string-length for CONTAINS_PATTERNS (default: 40)
```

Let us see the tool in action with an example with the already existing busybox checker:

First, we download some packages for Busybox, the directory looks something like this:

```
.
├── busybox-1.33.1-1.fc35.x86_64.rpm
└── busybox_1.30.1-4ubuntu9_amd64.deb
```

Now, we run the script. In this case, running the script for both windows and linux would result in something like this:

```
windows > python -m cve_bin_tool.helper_script busybox-1.33.1-1.fc35.x86_64.rpm --product busybox --version 1.33.1
linux $ python3 -m cve_bin_tool.helper_script busybox-1.33.1-1.fc35.x86_64.rpm --product busybox --version 1.33.1
────────────────────────────────────────────────────────── BusyboxChecker ───────────────────────────────────────────────────────────

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for busybox:

<provide reference links here>
"""
from cve_bin_tool.checkers import Checker


class BusyboxChecker(Checker):
        CONTAINS_PATTERNS = [
                r"BusyBox is a multi-call binary that combines many common Unix",
                r"BusyBox is copyrighted by many authors between 1998-2015.",
                r"BusyBox v1.33.1 (2021-05-06 17:29:07 UTC)",
                r"crond (busybox 1.33.1) started, log level %d",
                r"link to busybox for each function they wish to use and BusyBox",
        ]
        FILENAME_PATTERNS = [
                r"busybox", <--- this is a really common filename pattern
        ]
        VERSION_PATTERNS = [
                r"BusyBox v1.33.1 (2021-05-06 17:29:07 UTC)",
                r"crond (busybox 1.33.1) started, log level %d",
                r"SERVER_SOFTWARE=busybox httpd/1.33.1",
                r"syslogd started: BusyBox v1.33.1",
                r"tar (busybox) 1.33.1",
                r"fsck (busybox 1.33.1)",
        ]
        VENDOR_PRODUCT = [('busybox', 'busybox'), ('rob_landley', 'busybox')]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Try this against a few more `busybox` packages across different `distros` and see which strings are common among the following. Then follow the above steps to create the checker.

To get common strings for `CONTAINS_PATTERNS` in multiple `busybox` packages, we can use the script like this:

```
windows > python3 -m cve_bin_tool.helper_script busybox_1.30.1-4ubuntu6_amd64.deb busybox-1.33.0-3.fc34.x86_64.rpm --product busybox
linux $ python3 -m cve_bin_tool.helper_script busybox_1.30.1-4ubuntu6_amd64.deb busybox-1.33.0-3.fc34.x86_64.rpm --product busybox
─────────────────────────────────────────────────────── Common CONTAINS_PATTERNS strings for BusyboxChecker──────────────────────────

class BusyboxChecker(Checker):
 CONTAINS_PATTERNS = [
                r"BusyBox is a multi-call binary that combines many common Unix",
                r"BusyBox is copyrighted by many authors between 1998-2015.",
                r"link to busybox for each function they wish to use and BusyBox",
 ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

> _***NOTE:*** If you look at our existing checkers, you'll see that some strings are commented out in `CONTAINS_PATTERNS`. These strings are kept there as potential strings in case if the currently used strings stop working in the future versions. If you also find more than 2-3 strings, it's recommended to comment them out for future reference._

Currently, if you receive multiple vendor-product pairs, select the appropriate vendor-product pair from the following pairs obtained manually. In this case, it is `[('busybox', 'busybox')]`.

Since `VERSION_PATTERNS` returned by Helper-Script gives us a lists of some of the possible candidates for version strings. So, form the required regular expression by selecting the appropriate version string candidate. A good place to start would be to use python's in-built [`re`](https://docs.python.org/3/library/re.html) module or alternatively you could use [pythex.org](https://pythex.org/) - which let's you check if a given regex works the way you intend it to work. In this case, the obtained regex pattern is `"BusyBox v([0-9]+\.[0-9]+\.[0-9]+)"`.

## Adding tests

There are two types of tests you want to add to prove that your checker works as expected:

1. Test to show that the cve mapping works as expected.  
2. Tests to show that the checker correctly detects real binaries.

You can read about how to add these in
[tests/README.md](https://github.com/intel/cve-bin-tool/blob/main/test/README.md)

## Running tests

To run the tests for `cve-bin-tool`

```console
pytest
```

To run tests for a particular checker

```console
pytest -k $checkername
```

Alternatively you can run Long Tests using

```console
LONG_TESTS=1 pytest -k $checkername
```

You can run tests in parallel by using

```console
pytest -n 4
```

>This will spawn 4 worker processes to leverage multicore system.  
You can set an arbitrary number of workers. A good rule of thumb is to specify no. of workers equal to no. of cores.

## How it works

The CVE-bin-checker works by extracting strings from binaries and determining
if a given library has been compiled into the binary. For this, Checker class
contains two methods: 1) `guess_contains()` and 2) `get_version()`.

1. `guess_contains()` method takes list of extracted string lines as an input and
return True if it finds any of the `CONTAINS_PATTERNS` on any line from the
lines.
2. `get_version()` method takes list of extracted string lines and the filename as
inputs and returns information about whether the binary contains the library
in question, is a copy of the library in question, and if either of those are
true it also returns a version string. If the binary does not contain the
library, this function returns an empty dictionary.

If `curl` product is being scanned, `get_version()` method of CurlChecker will
return following dictionary.

```json
{
  "is_or_contains": "is",
  "modulename": "curl",
  "version": "6.41.0"
}
```

In most of the cases, Just providing above five class attributes will be enough.
But sometimes, you need to override this method to correctly detect version of
the product. We have done this in the checkers of `python` and`sqlite`.

## Updating checker table

You do not need to run format_checkers.py to update the checker table in documentation.
A pull request with updated checker table is created automatically when a new checker is merged.

## Pull Request Template

When you are ready to share your code, you can go to [our pull request page](https://github.com/intel/cve-bin-tool/pulls) to make a new pull request from the web interface and to use the guided template for new checker, click on the `Compare & pull request` button and add `?template=new_checker.md` at the end of the url.
