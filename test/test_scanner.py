# pylint: disable=too-many-public-methods, too-many-arguments, fixme
"""
CVE-bin-tool tests
"""
import itertools
import os
import shutil
import subprocess
import tempfile
import unittest
from sys import platform

import pytest

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.cli import Scanner, InvalidFileError
from test.utils import download_file, LONG_TESTS

BINARIES_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "binaries")


class TestScanner:
    """Runs a series of tests against our "faked" binaries.

    The faked binaries are very small c files containing the same string signatures we use
    in the cve-bin-tool.  They should trigger results as if they contained the library and
    version specified in the file name.

    At this time, the tests work only in python3.
    """

    @classmethod
    def setup_class(cls):
        # Run makefile to build faked binaries (in python 3 or 2)
        if platform == "linux" or platform == "linux2":
            subprocess.call(["make", "clean-linux"], cwd=BINARIES_PATH)
        elif platform == "win32":
            subprocess.call(["make", "clean-windows"], cwd=BINARIES_PATH)
        subprocess.call(["make", "all"], cwd=BINARIES_PATH)
        # Instantiate the NVD database
        cls.cvedb = CVEDB()
        if os.getenv("UPDATE_DB") == "1":
            cls.cvedb.get_cvelist_if_stale()
        else:
            print("Skip NVD database updates.")
        # Instantiate a scanner
        cls.scanner = Scanner(cls.cvedb)
        # temp dir for tests that require downloads
        cls.tempdir = tempfile.mkdtemp(prefix="cve-bin-tool-")

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.tempdir)

    def setup_method(self):
        self.cvedb.open()

    def teardown_method(self):
        self.cvedb.close()

    def scan_file(self, filename):
        """ Run the scanner on a file """
        return self.scanner.scan_file(os.path.join(BINARIES_PATH, filename))

    def test_vendor_package_pairs(self):
        """ Test the vendor/package pairs for NVD lookup """
        pairs = list(
            self.scanner.vendor_package_pairs(
                "\n".join(["VPkg: haxx, curl", "VPkg: feed, face"])
            )
        )
        assert pairs
        assert "haxx" in dict(pairs)
        assert "curl" in dict(map(lambda x: x[::-1], pairs))
        assert "feed" in dict(pairs)
        assert "face" in dict(map(lambda x: x[::-1], pairs))

    def test_does_not_scan_symlinks(self):
        """ Test that the scanner doesn't scan symlinks """
        os.symlink("non-existant-file", "non-existant-link")
        try:
            assert self.scanner.scan_file("non-existant-link") is None
        finally:
            os.unlink("non-existant-link")

    def test_cannot_open_file(self):
        """ Test behaviour when file cannot be opened """
        with pytest.raises(InvalidFileError):
            self.scan_file("non-existant-file")

    def _binary_test(self, binary, package, version, are_in, not_in):
        """ Helper function to scan a binary and check that it contains certain
        cves for a version and doesn't contain others."""
        # Run the scan
        cves = self.scan_file(binary)
        # Make sure the package and version are in the results
        assert package in list(cves.keys())
        assert version in list(cves[package].keys())
        # Test for CVEs known in this version
        for ensure_in in are_in:
            assert ensure_in in list(cves[package][version].keys())
        # Test for a CVE that is not in this version
        for ensure_out in not_in:
            assert ensure_out not in list(cves[package][version].keys())

    def _file_test(self, url, filename, package, version):
        """ Helper function to get a file (presumed to be a real copy
        of a library, probably from a Linux distribution) and run a
        scan on it.  Any test using this should likely be listed as a
        long test."""
        # get file
        tempfile = os.path.join(self.tempdir, filename)
        download_file(url + filename, tempfile)
        # new scanner for the new test.
        self.scanner = Scanner(cvedb=self.cvedb)
        # run the tests
        cves = self.scanner.extract_and_scan(tempfile)

        # make sure we found the expected package/version
        assert package in cves
        assert version in cves[package]

    @pytest.mark.parametrize(
        "binary, package, version, are_in, not_in",
        [
            (
                "test-bluetoothctl-5.42libbluetooth.so.out",
                "bluetoothctl",
                "5.42",
                [
                    # for known CVE
                    "CVE-2016-9797",
                    "CVE-2016-9798",
                    "CVE-2016-9799",
                    "CVE-2016-9800",
                    "CVE-2016-9801",
                    "CVE-2016-9802",
                    "CVE-2016-9803",
                    "CVE-2016-9804",
                    "CVE-2016-9917",
                    # "CVE-2016-9918",
                ],
                [
                    # for older version
                    "CVE-2016-7837"
                ],
            ),
            (
                "test-cups-1.2.4.out",
                "cups",
                "1.2.4",
                [
                    # Check for known cves in this version
                    "CVE-2007-5849",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2005-0206"
                ],
            ),
            (
                "test-icu-3.8.1.out",
                "international_components_for_unicode",
                "3.8.1",
                ["CVE-2007-4770", "CVE-2007-4771"],
                ["CVE-2019-3823"],
            ),
            (
                "test-icu-dos.out",
                "international_components_for_unicode",
                "3.8.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1",
                ["CVE-2014-9911"],
                ["CVE-2019-3823"],
            ),
            (
                "test-curl-7.34.0.out",
                "curl",
                "7.34.0",
                [
                    "CVE-2019-3823",
                    "CVE-2018-14618",
                    "CVE-2017-1000101",
                ],  # CVE-2017-1000101 needs supplemental data
                # From NVD : CVE-2017-1000101 affects 7.35.0 to 7.55.0
                [],
            ),
            (
                "test-curl-7.57.0.out",
                "curl",
                "7.57.0",
                [
                    "CVE-2018-1000122",
                    "CVE-2018-1000121",
                    "CVE-2018-1000120",
                    "CVE-2018-1000007",
                    # NOTE Missing from NVD as of 1/14/2019, reported to NVD
                    # fixed as of 1/15/2020
                    "CVE-2018-1000005",
                ],
                ["CVE-2017-8818"],
            ),
            (
                "test-curl-7.59.0.out",
                "curl",
                "7.59.0",
                [
                    # Check for known cves in 7.59.0
                    "CVE-2018-1000301",
                    "CVE-2018-1000300",
                ],
                ["CVE-2017-9502"],
            ),
            (
                "test-curl-7.65.0.out",
                "curl",
                "7.65.0",
                ["CVE-2019-5482", "CVE-2019-5481", "CVE-2019-5443",],
                ["CVE-2017-9502", "CVE-2018-1000301", "CVE-2018-1000300",],
            ),
            (
                "test-expat-2.2.2.out",
                "expat",
                "2.2.2",
                [
                    # Check for known cves in this version
                    "CVE-2018-20843",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2012-0876"
                ],
            ),
            (
                "test-expat-2.0.1.out",
                "expat",
                "2.0.1",
                [
                    # Check for issues specific to expat 2.0.1
                    "CVE-2012-1147",
                    # "CVE-2009-3720",
                    # "CVE-2009-3560",
                    "CVE-2012-1148",
                    "CVE-2012-0876",
                    # Check for other issues from more recent versions
                    # 2.1
                    # "CVE-2016-4472",
                    # "CVE-2016-5300",
                    # "CVE-2012-6702",
                    # "CVE-2015-1283",
                    # 2.2
                    # "CVE-2017-9233",
                    # "CVE-2016-9063",
                    # "CVE-2016-0718", Changed in nvd1.1 to not be caught
                    # "CVE-2017-11742",
                ],
                ["CVE-blahblah"],
            ),
            (
                "test-libjpeg-turbo-2.0.1.out",
                "libjpeg-turbo",
                "2.0.1",
                [
                    # two known cves in 2.0.1
                    "CVE-2018-20330",
                    "CVE-2018-19664",
                ],
                [
                    # check to make sure an older cve from 1.5.90 isn't included
                    "CVE-2018-1152"
                ],
            ),
            (
                "test-ffmpeg-4.1.3.out",
                "ffmpeg",
                "4.1.3",
                [
                    # known cves in 4.1.3
                    "CVE-2019-13312"
                ],
                [
                    # an older cve from before 4.1.3
                    "CVE-2019-11339"
                ],
            ),
            (
                "test-libjpeg-turbo-2.0.1.out",
                "libjpeg-turbo",
                "2.0.1",
                [
                    # two known cves in 2.0.1
                    "CVE-2018-20330",
                    "CVE-2018-19664",
                ],
                [
                    # check to make sure an older cve from 1.5.90 isn't included
                    "CVE-2018-1152"
                ],
            ),
            (
                "test-kerberos-5-1.15.1.out",
                "kerberos",
                "5-1.15.1",
                ["CVE-2018-5730"],
                ["CVE-2019-3823"],
            ),
            (
                "test-kerberos-5-1.15.1.out",
                "kerberos_5",
                "1.15.1",
                ["CVE-2017-11462", "CVE-2017-11368"],
                ["CVE-2019-3823"],
            ),
            (
                "test-kerberos-dos.out",
                "kerberos",
                "5-1.15.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1",
                ["CVE-2018-5730"],
                ["CVE-2019-3823"],
            ),
            (
                "test-nessus-6.8.1.out",
                "nessus",
                "6.8.1",
                [
                    # Check for known cves in this version
                    "CVE-2017-5179",
                    "CVE-2017-2122",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2014-2848"
                ],
            ),
            (
                "test-libdb-11.2.5.1.29.out",
                "libdb",
                "11.2.5.1.29",
                ["CVE-2015-2654", "CVE-2015-4790"],
                ["CVE-2019-2871"],
            ),
            (
                "test-libgcrypt-1.7.6.out",
                "libgcrypt",
                "1.7.6",
                [
                    # Check for known cves in this version
                    "CVE-2017-9526"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2014-5270"
                ],
            ),
            (
                "test-lighttpd-1.4.30.out",
                "lighttpd",
                "1.4.30",
                [
                    # Check for known cves in this version
                    "CVE-2013-4508"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2008-4298"
                ],
            ),
            (
                "test-libgcrypt-1.6.0.out",
                "libgcrypt",
                "1.6.0",
                [
                    # Check for known cves in this version
                    "CVE-2016-6313"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2013-4242"
                ],
            ),
            (
                "test-node-9.3.0.out",
                "node",
                "9.3.0",
                [
                    # Check for known cves in 9.3.0
                    "CVE-2017-15896",
                    "CVE-2017-15897",
                ],
                [
                    # Check to make sure an older CVE from 8.7.0 isn't included
                    "CVE-2017-14919"
                ],
            ),
            (
                "test-gnutls-cli-2.3.11.out",
                "gnutls-cli",
                "2.3.11",
                [
                    # known cves in 2.3.11
                    "CVE-2008-1948",
                    "CVE-2008-1949",
                    "CVE-2008-1950",
                ],
                [
                    # an older cve from before 2.3.11
                    "CVE-2004-2531",
                    # an newer cve from after 2.3.11
                    # "CVE-2017-7869", # The nvd data says this applies to anything before 3.5.9
                    "CVE-2019-3836",  # affects gnutls 3.6.3 -> 3.666
                ],
            ),
            (
                "test-gnutls-serv-2.3.11.out",
                "gnutls-cli",
                "2.3.11",
                [
                    # known cves in 2.3.11
                    "CVE-2008-1948",
                    "CVE-2008-1949",
                    "CVE-2008-1950",
                ],
                [
                    # an older cve from before 2.3.11
                    "CVE-2004-2531",
                    # an newer cve from after 2.3.11
                    # "CVE-2017-7869", # The nvd data says this applies to anything before 3.5.9
                    "CVE-2019-3836",  # affects gnutls 3.6.3 -> 3.666
                ],
            ),
            (
                "test-ncurses-6.1.out",
                "ncurses",
                "6.1",
                ["CVE-2018-19211"],
                [
                    # Check to make sure older CVEs aren't included
                    "CVE-2017-13734",
                    "CVE-2017-13731",
                ],
            ),
            (
                "test-nss-3.35.out",
                "nss",
                "3.35",
                [
                    # Check for known cves in 3.35
                    # "CVE-2017-11695", these have the version set to - which NIST says means n/a
                    # "CVE-2017-11696",
                    # "CVE-2017-11697",
                    # "CVE-2017-11698",a
                    "CVE-2018-12404",
                    "CVE-2018-12384",
                ],
                [
                    # Check to make sure an older CVE from 3.30.1 isn't included
                    "CVE-2017-7502"
                ],
            ),
            (
                "test-nss-3.37.1.out",
                "nss",
                "3.37.1",
                [
                    # Check for known cves in 3.37.1
                    "CVE-2018-12404",
                    "CVE-2018-12384",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2017-7502"
                ],
            ),
            (
                "test-nss-3.45.out",
                "nss",
                "3.45",
                [
                    # Check for known cves in 3.45
                    # "CVE-2017-11695", these have the version set to - which NIST says means n/a
                    # "CVE-2017-11696",
                    # "CVE-2017-11697",
                    # "CVE-2017-11698",
                    # "CVE-2018-12433",
                    # "CVE-2018-12437",
                    # "CVE-2018-12438",
                ],
                [
                    # check that older nss cves are not included
                    "CVE-2009-2409",
                    "CVE-2009-2408",
                    "CVE-2009-1938",
                ],
            ),
            (
                "test-openssh-7.9.out",
                "openssh-client",
                "7.9",
                [
                    # known CVEs in this version
                    "CVE-2019-6111",
                    "CVE-2019-6110",
                    "CVE-2019-6109",
                    "CVE-2018-20685",
                ],
                [
                    # older CVEs that should not be detected
                    "CVE-2018-15919",
                    "CVE-2018-15473",
                ],
            ),
            (
                "test-openssl-1.0.2g.out",
                "openssl",
                "1.0.2g",
                [
                    # Check for known cves in this version
                    "CVE-2016-2107",
                    "CVE-2016-2105",
                    "CVE-2016-2106",
                    "CVE-2016-2109",
                    "CVE-2016-2176",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2016-0800"
                ],
            ),
            (
                "test-openssl-1.1.0g.out",
                "openssl",
                "1.1.0g",
                [
                    # Check for known cves in this version
                    "CVE-2018-0739",
                    "CVE-2018-0733",
                    "CVE-2017-3738",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2017-3736",
                    "CVE-2017-3735",
                ],
            ),
            (
                "test-openssl-1.1.1d.out",
                "openssl",
                "1.1.1d",
                [
                    # Check for known cves in this version
                    "CVE-2019-1551",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2019-1563",
                    "CVE-2019-1552",
                    "CVE-2019-1547",
                ],
            ),
            (
                "test-openssh-6.9.out",
                "openssh-client",
                "6.9",
                [
                    # known CVEs in this version
                    "CVE-2015-6565",
                ],
                [
                    # older CVEs that should not be detected
                    "CVE-2000-0217",
                ],
            ),
            (
                "test-openswan-2.6.30.out",
                "openswan",
                "2.6.30",
                [
                    # Check for known cves in this version
                    "CVE-2013-6466",
                    "CVE-2013-2053",
                    "CVE-2011-4073",
                    "CVE-2011-3380",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2008-4190"
                ],
            ),
            (
                "test-png-1.4.11.out",
                "png",
                "1.4.11",
                [
                    # Check for known cves in this version
                    "CVE-2016-10087",
                    "CVE-2015-8540",
                    "CVE-2015-8472",
                    "CVE-2015-7981",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2012-3425"
                ],
            ),
            (
                "test-png-1.5.12.out",
                "png",
                "1.5.12",
                [
                    # Check for known cves in this version
                    "CVE-2017-12652"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2012-3425"
                ],
            ),
            (
                "test-png-1.6.26.out",
                "png",
                "1.6.26",
                [
                    # Check for known cves in this version
                    "CVE-2016-10087"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2015-8126"
                ],
            ),
            (
                "test-png-1.6.36.out",
                "png",
                "1.6.36",
                [
                    # Check for known cves in this version
                    "CVE-2019-6129"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2012-3425"
                ],
            ),
            (
                "test-postgresql-9.4.3.out",
                "postgresql",
                "9.4.3",
                [
                    # Check for known cves in this version
                    "CVE-2019-9193",
                    "CVE-2018-16850",
                    "CVE-2018-10925",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2010-4015"
                ],
            ),
            (
                "test-bzip2-1.0.2.out",
                "bzip2",
                "1.0.2",
                [
                    # Check for known cves in this version
                    "CVE-2005-0953",
                    "CVE-2008-1372",
                    "CVE-2010-0405",
                    "CVE-2011-4089",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2002-0760"
                ],
            ),
            (
                "test-b.zip2-1.0.2_imprv_covrg.out",
                "bzip2",
                "1.0.2",
                [
                    # Check for known cves in this version
                    "CVE-2005-0953",
                    "CVE-2008-1372",
                    "CVE-2010-0405",
                    "CVE-2011-4089",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2002-0760"
                ],
            ),
            (
                "test-sqlite-3.12.2.out",
                "sqlite",
                "3.12.2",
                [
                    # Check for known cves in this version
                    "CVE-2016-6153"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2013-7443"
                ],
            ),
            (
                "test-sqlite-3.16.1.out",
                "sqlite",
                "3.16.1",
                [
                    # Check for known cves in this version
                    "CVE-2019-16168",
                    "CVE-2019-8457",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2013-7443",
                    "CVE-2016-6153",
                ],
            ),
            (
                "test-sqlite-3.30.1.out",
                "sqlite",
                "3.30.1",
                [
                    # Check for known cves in this version
                    "CVE-2019-19242",
                    "CVE-2019-19244",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2013-7443",
                    "CVE-2016-6153",
                ],
            ),
            (
                "test-tiff-4.0.2.out",
                "tiff",
                "4.0.2",
                [
                    # Check for known cves in this version
                    "CVE-2018-5360",
                    "CVE-2013-4244",
                    "CVE-2013-4243",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2008-2327"
                ],
            ),
            (
                "test-systemd-239.out",
                "systemd",
                "239",
                [
                    # Check for known cves in this version
                    "CVE-2018-15688",
                    "CVE-2018-15687",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2017-9445"
                ],
            ),
            (
                "test-rsyslog-5.5.6.out",
                "rsyslog",
                "5.5.6",
                [
                    # Check for known cves in this version
                    "CVE-2018-16881",
                    "CVE-2011-4623",
                    "CVE-2011-3200",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2008-5617"
                ],
            ),
            (
                "test-xml2-2.9.0.out",
                "xml2",
                "2.9.0",
                [
                    # Check for known cves in this version
                    "CVE-2013-0338",
                    "CVE-2013-1969",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2011-1944"
                ],
            ),
            (
                "test-xml2-2.9.2.out",
                "xml2",
                "2.9.2",
                [
                    # Check for known cves in this version
                    "CVE-2015-7941",
                    "CVE-2015-7942",
                    "CVE-2015-8241",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2011-1944"
                ],
            ),
            (
                "test-xml2-2.9.3.out",
                "xml2",
                "2.9.3",
                [
                    # Check for known cves in this version
                    "CVE-2017-18258",
                    "CVE-2017-15412",
                    "CVE-2017-7376",
                    "CVE-2017-5130",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2011-1944"
                ],
            ),
            (
                "test-gnutls-cli-2.1.6.out",
                "gnutls-cli",
                "2.1.6",
                [
                    # known cves in 2.1.6
                    "CVE-2009-2730",
                    "CVE-2009-2409",
                    "CVE-2009-1417",
                ],
                [
                    # an older cve from before 2.1.6
                    "CVE-2004-2531",
                    # an newer cve from after 2.1.6
                    "CVE-2019-3836",
                ],
            ),
            (
                "test-gnutls_cli-2.1.6_imprv_covrg.out",
                "gnutls-cli",
                "2.1.6",
                [
                    # known cves in 2.1.6
                    "CVE-2009-2730",
                    "CVE-2009-2409",
                    "CVE-2009-1417",
                ],
                [
                    # an older cve from before 2.1.6
                    "CVE-2004-2531",
                    # an newer cve from after 2.1.6
                    "CVE-2019-3836",
                ],
            ),
            (
                "test-gnutls-serv-2.1.6.out",
                "gnutls-cli",
                "2.1.6",
                [
                    # known cves in 2.1.6
                    "CVE-2009-2730",
                    "CVE-2009-2409",
                    "CVE-2009-1417",
                ],
                [
                    # an older cve from before 2.1.6
                    "CVE-2004-2531",
                    # an newer cve from after 2.1.6
                    "CVE-2019-3836",
                ],
            ),
            (
                "test-bzip2-1.0.3.out",
                "bzip2",
                "1.0.3",
                [
                    # Check for known cves in this version
                    "CVE-2011-4089",
                    "CVE-2010-0405",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2005-0953"
                ],
            ),
            (
                "test-nginx-1.13.2.out",
                "nginx",
                "1.13.2",
                [
                    # Check for known cves in this version
                    "CVE-2017-7529"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2016-0747",
                    "CVE-2014-3616",
                ],
            ),
            (
                "test-tiff-4.0.9.out",
                "tiff",
                "4.0.9",
                [
                    # Check for known cves in this version
                    "CVE-2017-18013",
                    "CVE-2017-17942",
                    "CVE-2017-17095",
                    "CVE-2018-5784",
                    "CVE-2018-7456",
                    "CVE-2018-8905",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2017-17973"
                ],
            ),
            (
                "test-wireshark-1.10.12.out",
                "wireshark",
                "1.10.12",
                [
                    # Check for known cves in this version
                    "CVE-2015-3814",
                    "CVE-2015-3182",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2006-5740"
                ],
            ),
            (
                "test-xerces-3_1_1.out",
                "xerces",
                "3.1.1",
                [
                    # Check for known cves in this version
                    "CVE-2015-0252"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-EOL-DONOTUSE"
                ],
            ),
            (
                "test-hostapd-2.4.out",
                "hostapd",
                "2.4",
                [
                    # Check for known cves in this version
                    "CVE-2019-16275",
                    "CVE-2019-13377",
                    "CVE-2019-11555",
                    "CVE-2017-13088",
                    "CVE-2017-13087",
                    "CVE-2017-13086",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2012-2389"
                ],
            ),
            (
                "test-strongswan-4.6.3.out",
                "strongswan",
                "4.6.3",
                [
                    # Check for known cves in this version
                    "CVE-2019-10155",
                    "CVE-2018-17540",
                    "CVE-2018-16152",
                    "CVE-2018-16151",
                    "CVE-2018-5388",
                    "CVE-2015-8023",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2004-0590"
                ],
            ),
            (
                "test-syslogng-3.2.3.out",
                "syslog-ng",
                "3.2.3",
                [
                    # Check for known cves in this version
                    "CVE-2011-1951",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2002-1200"
                ],
            ),
            (
                "test-zlib-1.2.8.out",
                "zlib",
                "1.2.8",
                [
                    # Check for known cves in this version
                    "CVE-2016-9843",
                    "CVE-2016-9842",
                    "CVE-2016-9841",
                    "CVE-2016-9840",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2005-2096"
                ],
            ),
            (
                "test-python-3.7.1.out",
                "python",
                "3.7.1",
                [
                    # Check for known cves in this version
                    "CVE-2019-16935"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2017-17522"
                ],
            ),
            (
                "test-py_thon-3.7.1_1.out",
                "python",
                "3.7.1",
                [
                    # Check for known cves in this version
                    "CVE-2019-16935"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2017-17522"
                ],
            ),
            (
                "test-py_thon-3.7.1_2.out",
                "python",
                "3.7.1",
                [
                    # Check for known cves in this version
                    "CVE-2019-16935"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2017-17522"
                ],
            ),
            (
                "test-py_thon-3.7.1_3.out",
                "python",
                "3.7.1",
                [
                    # Check for known cves in this version
                    "CVE-2019-16935"
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2017-17522"
                ],
            ),
            (
                "test-python-3.7.2.out",
                "python",
                "3.7.2",
                ["CVE-2019-9636", "CVE-2019-9740", "CVE-2019-9947"],
                [
                    # "CVE-2018-1060"
                ],
            ),
            (
                "test-python-2.7.out",
                "python",
                "2.7.0",
                [
                    # check for known CVEs in this version
                    "CVE-2019-9948",  # Vulnerability type: Bypass
                    "CVE-2018-1000802",  # Vulnerability type: DoS
                    "CVE-2014-7185",  # Vulnerability type: Overflow
                ],
                [
                    # check to make sure other CVE related to same product is not included
                    "CVE-2018-1000117",
                ],
            ),
            (
                "test-gstreamer-1.10.0.out",
                "gstreamer",
                "1.10.0",
                ["CVE-2016-9445",],
                ["CVE-2016-9447",],
            ),
            (
                "test-varnish-4.1.1.out",
                "varnish",
                "4.1.1",
                [
                    # Check for known cves in this version
                    "CVE-2017-12425",
                    "CVE-2017-8807",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2013-4484",
                    "CVE-2013-0345",
                ],
            ),
            (
                "test-var.nish-4.1.1_imprv_covrg.out",
                "varnish",
                "4.1.1",
                [
                    # Check for known cves in this version
                    "CVE-2017-12425",
                    "CVE-2017-8807",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2013-4484",
                    "CVE-2013-0345",
                ],
            ),
            (
                "test-binutils-2.31.1.out",
                "binutils",
                "2.31.1",
                [
                    # Check for known cves
                    # Commented out because NVD data has only the last version
                    # 'CVE-2018-1000876',
                    "CVE-2018-20671",
                    # 'CVE-2018-20712',
                ],
                [
                    # check for an older cve that should not apply
                    "CVE-2018-10534",
                    "CVE-2018-7208",
                ],
            ),
            (
                "test-zlib-1.2.2.out",
                "zlib",
                "1.2.2",
                [
                    # Check for known cves in this version
                    "CVE-2005-2096",
                    "CVE-2005-1849",
                ],
                [
                    # Check to make sure an older CVE isn't included
                    "CVE-2016-9843"
                ],
            ),
        ],
    )
    def test_binaries(self, binary, package, version, are_in, not_in):
        self._binary_test(binary, package, version, are_in, not_in)

    @pytest.mark.parametrize(
        "url, filename, package, version",
        list(
            itertools.chain(
                [
                    (
                        "https://kojipkgs.fedoraproject.org/packages/cups/1.3.3/1.fc8/x86_64/",
                        "cups-1.3.3-1.fc8.x86_64.rpm",
                        "cups",
                        "1.3.3",
                    ),
                    (
                        "https://archives.fedoraproject.org/pub/archive/fedora/linux"
                        "/releases/20/Everything/x86_64/os/Packages/c/",
                        "curl-7.32.0-3.fc20.x86_64.rpm",
                        "curl",
                        "7.32.0",
                    ),
                    (
                        "https://rpmfind.net/linux/openmandriva/4.0/repository"
                        "/aarch64/main/release/",
                        "curl-7.65.0-2-omv4000.aarch64.rpm",
                        "curl",
                        "7.65.0",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "expat-2.1.0-11.el7.x86_64.rpm",
                        "expat",
                        "2.1.0",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/expat/2.2.1/1.fc24/x86_64/",
                        "expat-2.2.1-1.fc24.x86_64.rpm",
                        "expat",
                        "2.2.1",
                    ),
                    (
                        "http://http.us.debian.org/debian/pool/main/e/expat/",
                        "libexpat1_2.2.0-2+deb9u3_amd64.deb",
                        "expat",
                        "2.2.0",
                    ),
                    (
                        "http://archive.ubuntu.com/ubuntu/pool/universe/f/ffmpeg/",
                        "ffmpeg_4.1.4-1build2_amd64.deb",
                        "ffmpeg",
                        "4.1.4",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "gnutls-utils-3.3.29-9.el7_6.x86_64.rpm",
                        "gnutls-cli",
                        "3.3.29",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/openssh/6.8p1/1.1.fc23/x86_64/",
                        "openssh-clients-6.8p1-1.1.fc23.x86_64.rpm",
                        "openssh-client",
                        "6.8p1",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "krb5-libs-1.15.1-46.el7.x86_64.rpm",
                        "kerberos_5",
                        "1.15.1",
                    ),
                    (
                        "http://archive.ubuntu.com/ubuntu/pool/universe/g/gnutls28/",
                        "gnutls-bin_3.4.10-4ubuntu1.7_amd64.deb",
                        "gnutls-cli",
                        "3.4.10",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "libdb-5.3.21-25.el7.i686.rpm",
                        "libdb",
                        "11.2.5.3.21",  # Note that the full libdb version is longer than the package version
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/ncurses/6.2/1.20200222.fc33/x86_64/",
                        "ncurses-6.2-1.20200222.fc33.x86_64.rpm",
                        "ncurses",
                        "6.2",
                    ),
                    (
                        "http://rpmfind.net/linux/mageia/distrib/5/i586/media/core/updates/",
                        "openssl-1.0.2g-1.1.mga5.i586.rpm",
                        "openssl",
                        "1.0.2g",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/openswan/2.6.31/1.fc14/x86_64/",
                        "openswan-2.6.31-1.fc14.x86_64.rpm",
                        "openswan",
                        "2.6.31",
                    ),
                    (
                        "http://mirror.centos.org/centos/6/os/x86_64/Packages/",
                        "openswan-2.6.32-37.el6.x86_64.rpm",
                        "openswan",
                        "2.6.32",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org//packages/python3/3.8.2~rc1/1.fc33/aarch64/",
                        "python3-3.8.2~rc1-1.fc33.aarch64.rpm",
                        "python",
                        "3.8.2",
                    ),
                    (
                        "https://rpmfind.net/linux/openmandriva/4.0/repository/x86_64/main/release/",
                        "python-3.7.3-4-omv4000.x86_64.rpm",
                        "python",
                        "3.7.3",
                    ),
                    (
                        "http://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/",
                        "libjpeg-turbo-2.0.2-1.fc30.x86_64.rpm",
                        "libjpeg-turbo",
                        "2.0.2",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "libgcrypt-1.5.3-14.el7.x86_64.rpm",
                        "libgcrypt",
                        "1.5.3",
                    ),
                    (
                        "http://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/",
                        "libgcrypt-1.8.4-3.fc30.x86_64.rpm",
                        "libgcrypt",
                        "1.8.4",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/nginx/1.8.0/10.fc22/x86_64/",
                        "nginx-1.8.0-10.fc22.x86_64.rpm",
                        "nginx",
                        "1.8.0",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/postgresql/9.4.4/1.fc22/x86_64/",
                        "postgresql-9.4.4-1.fc22.x86_64.rpm",
                        "postgresql",
                        "9.4.4",
                    ),
                    (
                        "https://nodejs.org/dist/v12.16.1/",
                        "node-v12.16.1-linux-x64.tar.xz",
                        "node",
                        "12.16.1",
                    ),
                    (
                        "http://rpmfind.net/linux/openmandriva/3.0/repository/x86_64/main/updates/",
                        "nss-3.42.1-1-omv2015.0.x86_64.rpm",
                        "nss",
                        "3.42.1",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/nss/3.37.3/3.fc29/x86_64/",
                        "nss-3.37.3-3.fc29.x86_64.rpm",
                        "nss",
                        "3.37.3",
                    ),
                    (
                        "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/30/Everything/aarch64/os/Packages/n/",
                        "nessus-libraries-2.2.11-16.fc29.aarch64.rpm",
                        "nessus",
                        "2.2.11",
                    ),
                    (
                        "http://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/",
                        "libpng-1.6.36-1.fc30.x86_64.rpm",
                        "png",
                        "1.6.36",
                    ),
                    (
                        "https://mirrors.kernel.org/fedora/releases/31/Everything/x86_64/os/Packages/l/",
                        "lighttpd-1.4.54-2.fc31.x86_64.rpm",
                        "lighttpd",
                        "1.4.54",
                    ),
                    (
                        "https://ftp.lysator.liu.se/pub/opensuse/distribution/leap/15.1/repo/oss/x86_64/",
                        "lighttpd-1.4.49-lp151.2.3.x86_64.rpm",
                        "lighttpd",
                        "1.4.49",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "libpng-1.5.13-7.el7_2.x86_64.rpm",
                        "png",
                        "1.5.13",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/bzip2/1.0.4/10.fc7/x86_64/",
                        "bzip2-1.0.4-10.fc7.x86_64.rpm",
                        "bzip2",
                        "1.0.4",
                    ),
                    (
                        "http://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/",
                        "libtiff-4.0.10-4.fc30.i686.rpm",
                        "tiff",
                        "4.0.10",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "libtiff-4.0.3-32.el7.x86_64.rpm",
                        "tiff",
                        "4.0.3",
                    ),
                    (
                        "http://rpmfind.net/linux/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/",
                        "libxml2-2.9.9-2.fc30.x86_64.rpm",
                        "xml2",
                        "2.9.9",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "libxml2-2.9.1-6.el7.4.x86_64.rpm",
                        "xml2",
                        "2.9.1",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/strongswan/4.6.2/1.fc16/x86_64/",
                        "strongswan-4.6.2-1.fc16.x86_64.rpm",
                        "strongswan",
                        "4.6.2",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/varnish/4.0.5/1.el7/x86_64/",
                        "varnish-4.0.5-1.el7.x86_64.rpm",
                        "varnish",
                        "4.0.5",
                    ),
                    (
                        "http://rpmfind.net/linux/fedora/linux/updates/testing/31/Everything/aarch64/Packages/z/",
                        "zlib-1.2.11-19.fc31.aarch64.rpm",
                        "zlib",
                        "1.2.11",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/hostapd/2.3/1.fc20/x86_64/",
                        "hostapd-2.3-1.fc20.x86_64.rpm",
                        "hostapd",
                        "2.3",
                    ),
                    (
                        "http://security.ubuntu.com/ubuntu/pool/universe/w/wpa/",
                        "hostapd_2.1-0ubuntu1.7_amd64.deb",
                        "hostapd",
                        "2.1",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/rsyslog/5.5.7/1.fc15/x86_64/",
                        "rsyslog-5.5.7-1.fc15.x86_64.rpm",
                        "rsyslog",
                        "5.5.7",
                    ),
                    (
                        "http://mirror.centos.org/centos/6/os/x86_64/Packages/",
                        "bzip2-1.0.5-7.el6_0.x86_64.rpm",
                        "bzip2",
                        "1.0.5",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/sqlite/3.16.2/1.fc26/x86_64/",
                        "sqlite-3.16.2-1.fc26.x86_64.rpm",
                        "sqlite",
                        "3.16.2",
                    ),
                    (
                        "http://rpmfind.net/linux/atrpms/el4-x86_64/atrpms/stable/",
                        "sqlite-3.1.2-2.99_2.el4.at.i386.rpm",
                        "sqlite",
                        "3.1.2",
                    ),
                    (
                        "https://mirrors.kernel.org/fedora-buffet/archive/fedora/linux/releases/21/Everything/x86_64/os/Packages/s/",
                        "syslog-ng-3.5.6-3.fc21.x86_64.rpm",
                        "syslog-ng",
                        "3.5.6",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "systemd-219-73.el7.1.x86_64.rpm",
                        "systemd",
                        "219",
                    ),
                    (
                        "http://security.ubuntu.com/ubuntu/pool/main/s/systemd/",
                        "systemd_229-4ubuntu21.27_amd64.deb",
                        "systemd",
                        "229",
                    ),
                    (
                        "https://rpmfind.net/linux/openmandriva/4.0/repository/x86_64/main/release/",
                        "systemd-242.20190509-1-omv4000.x86_64.rpm",
                        "systemd",
                        "242",
                    ),
                    (
                        "https://rpmfind.net/linux/fedora/linux/releases/31/Everything/x86_64/os/Packages/s/",
                        "systemd-243-4.gitef67743.fc31.i686.rpm",
                        "systemd",
                        "243",
                    ),
                    (
                        "https://kojipkgs.fedoraproject.org/packages/wireshark/1.10.13/1.fc20/x86_64/",
                        "wireshark-1.10.13-1.fc20.x86_64.rpm",
                        "wireshark",
                        "1.10.13",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "wireshark-1.10.14-24.el7.x86_64.rpm",
                        "wireshark",
                        "1.10.14",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "xerces-c-3.1.1-9.el7.x86_64.rpm",
                        "xerces",
                        "3.1",  # FIXME: This is a bug in our detection on Centos
                    ),
                    (
                        "https://rpmfind.net/linux/centos/6.10/os/i386/Packages/",
                        "icu-4.2.1-14.el6.i686.rpm",
                        "international_components_for_unicode",
                        "4.2.1",
                    ),
                    (
                        "http://archive.ubuntu.com/ubuntu/pool/universe/g/gstreamermm-1.0/",
                        "libgstreamermm-1.0-0v5_1.4.3+dfsg-5_amd64.deb",
                        "gstreamer",
                        "1.0",
                    ),
                    (
                        "http://mirror.centos.org/centos/6/os/x86_64/Packages/",
                        "gstreamer-0.10.29-1.el6.x86_64.rpm",
                        "gstreamer",
                        "0.10",
                    ),
                    (
                        "http://security.ubuntu.com/ubuntu/pool/main/b/binutils/",
                        "binutils_2.26.1-1ubuntu1~16.04.8_amd64.deb",
                        "binutils",
                        "2.26.1",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "binutils-2.27-43.base.el7.x86_64.rpm",
                        "binutils",
                        "2.27",
                    ),
                    (
                        "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
                        "zlib-1.2.7-18.el7.x86_64.rpm",
                        "zlib",
                        "1.2.7",
                    ),
                    (
                        "http://archive.ubuntu.com/ubuntu/pool/main/z/zlib/",
                        "zlib1g_1.2.8.dfsg-2ubuntu4_amd64.deb",
                        "zlib",
                        "1.2.8",
                    ),
                ],
                list(
                    map(
                        lambda item: (
                            "http://xmlsoft.org/sources/",
                            item[0],
                            "xml2",
                            item[1],
                        ),
                        [
                            ["libxml2-2.7.2-1.x86_64.rpm", "2.7.2"],
                            ["libxml2-2.7.3-1.x86_64.rpm", "2.7.3"],
                            ["libxml2-2.7.4-1.x86_64.rpm", "2.7.4"],
                            ["libxml2-2.7.5-1.x86_64.rpm", "2.7.5"],
                            ["libxml2-2.7.6-1.x86_64.rpm", "2.7.6"],
                            ["libxml2-2.7.7-1.x86_64.rpm", "2.7.7"],
                            ["libxml2-2.7.8-1.x86_64.rpm", "2.7.8"],
                            ["libxml2-2.8.0-1.x86_64.rpm", "2.8.0"],
                            ["libxml2-2.9.0-0rc0.x86_64.rpm", "2.9.0"],
                            ["libxml2-2.9.0-0rc1.x86_64.rpm", "2.9.0"],
                            ["libxml2-2.9.0-0rc2.x86_64.rpm", "2.9.0"],
                            ["libxml2-2.9.0-1.x86_64.rpm", "2.9.0"],
                            ["libxml2-2.9.1-1.fc17.x86_64.rpm", "2.9.1"],
                            ["libxml2-2.9.2-0rc1.fc19.x86_64.rpm", "2.9.2"],
                            ["libxml2-2.9.2-0rc2.fc19.x86_64.rpm", "2.9.2"],
                            ["libxml2-2.9.2-1.fc19.x86_64.rpm", "2.9.2"],
                            ["libxml2-2.9.3-1.fc23.x86_64.rpm", "2.9.3"],
                            ["libxml2-2.9.4-0rc1.fc23.x86_64.rpm", "2.9.4"],
                            ["libxml2-2.9.4-0rc2.fc23.x86_64.rpm", "2.9.4"],
                            ["libxml2-2.9.4-1.fc23.x86_64.rpm", "2.9.4"],
                            ["libxml2-2.9.5-0rc1.fc24.x86_64.rpm", "2.9.5"],
                            ["libxml2-2.9.5-0rc2.fc24.x86_64.rpm", "2.9.5"],
                            ["libxml2-2.9.5-1.fc24.x86_64.rpm", "2.9.5"],
                            ["libxml2-2.9.6-0rc1.fc26.x86_64.rpm", "2.9.6"],
                            ["libxml2-2.9.6-1.fc26.x86_64.rpm", "2.9.6"],
                            ["libxml2-2.9.7-0rc1.fc26.x86_64.rpm", "2.9.7"],
                            ["libxml2-2.9.7-1.fc26.x86_64.rpm", "2.9.7"],
                            ["libxml2-2.9.8-0rc1.fc26.x86_64.rpm", "2.9.8"],
                            ["libxml2-2.9.8-1.fc26.x86_64.rpm", "2.9.8"],
                            ["libxml2-2.9.9-0rc1.fc28.x86_64.rpm", "2.9.9"],
                            ["libxml2-2.9.9-0rc2.fc28.x86_64.rpm", "2.9.9"],
                            ["libxml2-2.9.9-1.fc28.x86_64.rpm", "2.9.9"],
                        ],
                    )
                ),
            )
        ),
    )
    @unittest.skipUnless(LONG_TESTS() > 0, "Skipping long tests")
    def test_files(self, url, filename, package, version):
        self._file_test(url, filename, package, version)
