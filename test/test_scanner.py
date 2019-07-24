# pylint: disable=too-many-public-methods, too-many-arguments, fixme
"""
CVE-bin-tool tests
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from sys import platform

from cve_bin_tool.NVDAutoUpdate import NVDSQLite
from cve_bin_tool.cli import Scanner, InvalidFileError
from cve_bin_tool.extractor import Extractor
from .test_definitions import download_file

BINARIES_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "binaries")


class TestScanner(unittest.TestCase):
    """Runs a series of tests against our "faked" binaries.

    The faked binaries are very small c files containing the same string signatures we use
    in the cve-bin-tool.  They should trigger results as if they contained the library and
    version specified in the file name.

    At this time, the tests work only in python3.
    """

    @classmethod
    def setUpClass(cls):
        # Run makefile to build faked binaries (in python 3 or 2)
        if platform == "linux" or platform == "linux2":
            subprocess.call(["make", "clean-linux"], cwd=BINARIES_PATH)
        elif platform == "win32":
            subprocess.call(["make", "clean-windows"], cwd=BINARIES_PATH)
        subprocess.call(["make", "all"], cwd=BINARIES_PATH)
        # Instantiate the NVD database
        cls.nvd = NVDSQLite()
        if os.getenv("UPDATE_DB") == "1":
            cls.nvd.get_cvelist_if_stale()
        else:
            print("Skip NVD database updates.")
        # Instantiate a scanner
        cls.scanner = Scanner(cls.nvd)
        # temp dir for tests that require downloads
        cls.tempdir = tempfile.mkdtemp(prefix="cve-bin-tool-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tempdir)

    def setUp(self):
        self.nvd.open()

    def tearDown(self):
        self.nvd.close()

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
        self.assertTrue(pairs)
        self.assertIn("haxx", dict(pairs))
        self.assertIn("curl", dict(map(lambda x: x[::-1], pairs)))
        self.assertIn("feed", dict(pairs))
        self.assertIn("face", dict(map(lambda x: x[::-1], pairs)))

    def test_does_not_scan_symlinks(self):
        """ Test that the scanner doesn't scan symlinks """
        os.symlink("non-existant-file", "non-existant-link")
        try:
            self.assertIsNone(self.scanner.scan_file("non-existant-link"))
        finally:
            os.unlink("non-existant-link")

    def test_cannot_open_file(self):
        """ Test behaviour when file cannot be opened """
        with self.assertRaises(InvalidFileError):
            self.scan_file("non-existant-file")

    def _binary_test(self, binary, package, version, are_in, not_in):
        """ Helper function to scan a binary and check that it contains certain
        cves for a version and doesn't contain others."""
        # Run the scan
        cves = self.scan_file(binary)
        # Make sure the package and version are in the results
        self.assertIn(package, cves)
        self.assertIn(version, cves[package])
        # Test for CVEs known in this version
        for ensure_in in are_in:
            self.assertIn(ensure_in, cves[package][version])
        # Test for a CVE that is not in this version
        for ensure_out in not_in:
            self.assertNotIn(ensure_out, cves[package][version])

    def _file_test(self, url, filename, package, version):
        """ Helper function to get a file (presumed to be a real copy
        of a library, probably from a Linux distribution) and run a
        scan on it.  Any test using this should likely be listed as a
        long test."""
        # get file
        tempfile = os.path.join(self.tempdir, filename)
        download_file(url + filename, tempfile)

        # run the tests
        cves = self.scanner.extract_and_scan(tempfile)

        # make sure we found the expected package/version
        self.assertIn(package, cves)
        self.assertIn(version, cves[package])

    def test_icu_3_8_1(self):
        """Scanning test-icu-3.8.1.out"""
        self._binary_test(
            "test-icu-3.8.1.out",
            "international_components_for_unicode",
            "3.8.1",
            ["CVE-2007-4770", "CVE-2007-4771"],
            ["CVE-2019-3823"],
        )

    def test_curl_7_34_0(self):
        """Scanning test-curl-7.34.0.out"""
        self._binary_test(
            "test-curl-7.34.0.out",
            "curl",
            "7.34.0",
            ["CVE-2019-3823", "CVE-2018-14618", "CVE-2017-1000101"],
            [],
        )

    def test_curl_7_57_0(self):
        """Scanning test-curl-7.57.0.out"""
        self._binary_test(
            "test-curl-7.57.0.out",
            "curl",
            "7.57.0",
            [
                "CVE-2018-1000122",
                "CVE-2018-1000121",
                "CVE-2018-1000120",
                "CVE-2018-1000007",
                # NOTE Missing from NVD as of 1/14/2019, reported to NVD
                # 'CVE-2018-1000005',
            ],
            ["CVE-2017-8818"],
        )

    def test_curl_7_59_0(self):
        """Scanning test-curl-7.59.0.out"""
        self._binary_test(
            "test-curl-7.59.0.out",
            "curl",
            "7.59.0",
            [
                # Check for known cves in 7.59.0
                "CVE-2018-1000301",
                "CVE-2018-1000300",
            ],
            ["CVE-2017-9502"],
        )

    # @unittest.skipUnless(os.getenv('LONG_TESTS') == '1', 'Skipping long tests')
    def test_curl_rpm_7_32_0(self):
        """
        test to see if we detect a real copy of curl 7.32.0
        """
        self._file_test(
            "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/20/Everything/x86_64/os/Packages/c/",
            "curl-7.32.0-3.fc20.x86_64.rpm",
            "curl",
            "7.32.0",
        )

    def test_expat_2_0_1(self):
        """Scanning test-expat-2.0.1.out"""
        # TODO Commented out issues have to do with less than X.X.X version
        # issue with NVD. Issue #29
        self._binary_test(
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
                "CVE-2016-0718",
                # "CVE-2016-4472",
                # "CVE-2016-5300",
                # "CVE-2012-6702",
                # "CVE-2015-1283",
                # 2.2
                # "CVE-2017-9233",
                # "CVE-2016-9063",
                "CVE-2016-0718",
                # "CVE-2017-11742",
            ],
            ["CVE-blahblah"],
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_expat_rpm_2_1_0(self):
        """ Test detection of expat 2.1 centos package """
        self._file_test(
            "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
            "expat-2.1.0-10.el7_3.i686.rpm",
            "expat",
            "2.1.0",
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_expat_deb_2_2_0(self):
        """ Test detection of expat 2.2 debian package """
        self._file_test(
            "http://http.us.debian.org/debian/pool/main/e/expat/",
            "libexpat1_2.2.0-2+deb9u1_amd64.deb",
            "expat",
            "2.2.0",
        )

    def test_jpeg_2_0_1(self):
        """Scanning test-libjpeg-turbo-2.0.1"""
        self._binary_test(
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
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_jpeg_rpm_2_0_0(self):
        """ Test detection of libjpeg-turbo 2.0.0 fedora rpm """
        self._file_test(
            "http://mirrors.kernel.org/fedora/releases/29/Workstation/x86_64/os/Packages/l/",
            "libjpeg-turbo-2.0.0-1.fc29.x86_64.rpm",
            "libjpeg-turbo",
            "2.0.0",
        )

    def test_kerberos_1_15_1(self):
        """Scanning test-kerberos-5-1.15.1.out"""
        self._binary_test(
            "test-kerberos-5-1.15.1.out",
            "kerberos",
            "5-1.15.1",
            ["CVE-2017-11462", "CVE-2017-11368", "CVE-2018-5730"],
            ["CVE-2019-3823"],
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_kerberos_rpm_1_15_1(self):
        """ Test detection of krb5-libs (kerberos libraries) from Centos """
        self._file_test(
            "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
            "krb5-libs-1.15.1-34.el7.i686.rpm",
            "kerberos",
            "1.15.1",
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_kerberos_deb_1_15(self):
        """ Test detection of libkrb5 (kerberos libraries) from Debian """
        self._file_test(
            "http://http.us.debian.org/debian/pool/main/k/krb5/",
            "libkrb5-3_1.15-1+deb9u1_amd64.deb",
            "kerberos",
            "1.15",
        )

    def test_libgcrypt_1_7_6(self):
        """Scanning test-libgcrypt-1.7.6.out"""
        self._binary_test(
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
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_libgcrypt_rpm_1_8_3(self):
        """ Test detection of libgcrypt 1.8.3 fedora rpm """
        self._file_test(
            "http://mirrors.kernel.org/fedora/releases/29/Workstation/x86_64/os/Packages/l/",
            "libgcrypt-1.8.3-3.fc29.x86_64.rpm",
            "libgcrypt",
            "1.8.3",
        )

    def test_node_9_3_0(self):
        """Scanning test-node-9.3.0.out"""
        self._binary_test(
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
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_node_tgz_9_9_0(self):
        """ test detection of nodejs 9.9.0 tar.gz direct from nodejs.org """
        self._file_test(
            "https://nodejs.org/download/release/v9.9.0/",
            "node-v9.9.0-linux-x64.tar.gz",
            "node",
            "9.9.0",
        )

    def test_nss_3_35(self):
        """Scanning test-nss-3.55.out"""
        self._binary_test(
            "test-nss-3.35.out",
            "nss",
            "3.35",
            [
                # Check for known cves in 3.35
                "CVE-2017-11695",
                "CVE-2017-11696",
                "CVE-2017-11697",
                "CVE-2017-11698",
            ],
            [
                # Check to make sure an older CVE from 3.30.1 isn't included
                "CVE-2017-7502"
            ],
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_nss_rpm_3_26_2(self):
        """ test detection of mozilla nss 3.26.2 package from OpenSuSe """
        self._file_test(
            "https://rpmfind.net/linux/opensuse/update/leap/42.1/oss/x86_64/",
            "mozilla-nss-32bit-3.26.2-32.1.x86_64.rpm",
            "nss",
            "3.26.2",
        )

    def test_openssl_1_0_2g(self):
        """Scanning test-openssl-1.0.2g.out"""
        self._binary_test(
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
        )

    def test_openssl_1_1_0g(self):
        """Scanning test-openssl-1.1.0g.out"""
        self._binary_test(
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
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_openssl_rpm_1_0_2g(self):
        """
        test to see if we detect a real copy of openssl 1.2.2g
        """
        self._file_test(
            "http://rpmfind.net/linux/mageia/distrib/5/i586/media/core/updates/",
            "openssl-1.0.2g-1.1.mga5.i586.rpm",
            "openssl",
            "1.0.2g",
        )

    def test_png_1_4_11(self):
        """Scanning test-png-1_4_11.out"""
        self._binary_test(
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
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_png_rpm_1_6_34(self):
        """ Test detection of png 1.6.34 fedora rpm """
        self._file_test(
            "http://mirrors.kernel.org/fedora/releases/29/Workstation/x86_64/os/Packages/l/",
            "libpng-1.6.34-6.fc29.x86_64.rpm",
            "png",
            "1.6.34",
        )

    def test_png_1_6_26(self):
        """Scanning test-png-1.6.26.out"""
        self._binary_test(
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
        )

    def test_png_1_6_36(self):
        """Scanning test-png-1_6_36.out"""
        self._binary_test(
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
        )

    def test_sqlite_3_12_2(self):
        """Scanning test-sqlite-3.12.2.out"""
        self._binary_test(
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
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_sqlite_rpm_3_1_2(self):
        """
        test to see if we detect a real copy of sqlite 3.1.2
        """
        self._file_test(
            "http://rpmfind.net/linux/atrpms/el4-x86_64/atrpms/stable/",
            "sqlite-3.1.2-2.99_2.el4.at.i386.rpm",
            "sqlite",
            "3.1.2",
        )

    def test_systemd_239(self):
        """Scanning test-systemd-239.out"""
        self._binary_test(
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
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_systemd_rpm_219(self):
        """ test detection of a systemd 219 rpm from centos 7 """
        self._file_test(
            "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
            "systemd-219-62.el7.x86_64.rpm",
            "systemd",
            "219",
        )

    def test_tiff_4_0_9(self):
        """Scanning test-tiff-4.0.9.out"""
        self._binary_test(
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
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_tiff_rpm_4_0_9(self):
        """ Test detection on tiff 4.0.9 rpm from Fedora """
        self._file_test(
            "http://mirrors.kernel.org/fedora/releases/29/Workstation/x86_64/os/Packages/l/",
            "libtiff-4.0.9-11.fc29.x86_64.rpm",
            "tiff",
            "4.0.9",
        )

    def test_xerces_3_1_1(self):
        """Scanning test-xerces-3_1_1.out"""
        self._binary_test(
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
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_xerces_rpm_3_1_1(self):
        """ test detection on xerces-c 3.1.1 rpm from centos """
        self._file_test(
            "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
            "xerces-c-3.1.1-9.el7.x86_64.rpm",
            "xerces",
            "3.1",  # FIXME: This is a bug in our detection on Centos
        )

    def test_xml2_2_9_0(self):
        """Scanning test-xml2-2.9.0.out"""
        self._binary_test(
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
        )

    def test_xml2_2_9_2(self):
        """Scanning test-xml2-2.9.2.out"""
        self._binary_test(
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
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_xml2_rpm_2_9_1(self):
        """
        test to see if we detect a real copy of libxml2 2.9.1
        """
        self._file_test(
            "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
            "libxml2-2.9.1-6.el7_2.3.x86_64.rpm",
            "xml2",
            "2.9.1",
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_xml2_rpm_2_9_8(self):
        """ Test detection on libxml2 2.9.8 fedora rpm """
        self._file_test(
            "http://mirrors.kernel.org/fedora/releases/29/Workstation/x86_64/os/Packages/l/",
            "libxml2-2.9.8-4.fc29.x86_64.rpm",
            "xml2",
            "2.9.8",
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_xml2_rpm_all(self):
        """ Test detection of 32 xml2 binaries on the xmlsoft download page.
        (All the binaries as of the time this test was written) """
        rpmlist = [
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
        ]
        for rpm, version in rpmlist:
            print("rpm: {} version: {}".format(rpm, version))
            self._file_test("http://xmlsoft.org/sources/", rpm, "xml2", version)

    def test_zlib_1_2_8(self):
        """Scanning test-zlib-1.2.8.out"""
        self._binary_test(
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
        )

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_zlib_rpm_1_2_11(self):
        """ Test detection on zlib 1.2.11 fedora rpm """
        self._file_test(
            "http://mirrors.kernel.org/fedora/releases/29/Workstation/x86_64/os/Packages/z/",
            "zlib-1.2.11-14.fc29.x86_64.rpm",
            "zlib",
            "1.2.11",
        )
