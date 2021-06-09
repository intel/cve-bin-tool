# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

#!python
import re

import pkg_resources
import pytest

from cve_bin_tool.checkers import Checker, VendorProductPair

Pattern = type(re.compile("", 0))


class TestCheckerClass:
    def test_valid_checker(self):
        class MyChecker(Checker):
            CONTAINS_PATTERNS = [r"look"]
            VERSION_PATTERNS = [r"for"]
            FILENAME_PATTERNS = [r"myproduct"]
            VENDOR_PRODUCT = [("myvendor", "myproduct")]

        assert type(MyChecker.CONTAINS_PATTERNS[0]) == Pattern
        assert type(MyChecker.VERSION_PATTERNS[0]) == Pattern
        assert type(MyChecker.FILENAME_PATTERNS[0]) == Pattern
        assert type(MyChecker.VENDOR_PRODUCT[0]) == VendorProductPair

    def test_no_vpkg(self):
        with pytest.raises(AssertionError) as e:

            class MyChecker(Checker):
                CONTAINS_PATTERNS = [r"look"]
                VERSION_PATTERNS = [r"for"]
                FILENAME_PATTERNS = [r"myproduct"]
                PRODUCT_NAME = "mychecker"

        assert e.value.args[0] == "MyChecker needs at least one vendor product pair"


class TestCheckerVersionParser:
    """Run a series of tests directly against individual checkers.
    This is a companion to the tests in TestScanner."""

    @pytest.mark.parametrize(
        "checker_name, file_name, expected_results",
        [
            ("binutils", "dlltool", ["binutils"]),
            ("bzip2", "bzip2.so", ["bzip2"]),
            ("cups", "cupsd.so", ["cups"]),
            ("curl", "libcurl.so.4", ["curl"]),
            ("expat", "libexpat.so", ["expat"]),
            ("ffmpeg", "libffmpeg.so", ["ffmpeg"]),
            ("gnutls_cli", "libgnutls.so", ["gnutls-cli"]),
            ("gnutls_serv", "gnutls-serv", ["gnutls-serv"]),
            ("gstreamer", "libgstreamer.so", ["gstreamer"]),
            ("hostapd", "hostapd.so", ["hostapd"]),
            (
                "icu",
                "international_components_for_unicode.o",
                ["international_components_for_unicode"],
            ),
            ("kerberos", "kerberos", ["kerberos", "kerberos_5"]),
            ("libcurl", "libcurl.so.2.0", ["libcurl"]),
            ("libdb", "libdb-2.0.so", ["libdb"]),
            ("libgcrypt", "libgcrypt.so.1.0", ["libgcrypt"]),
            ("libjpeg", "libjpg.so.2.0", ["libjpeg-turbo"]),
            ("libnss", "libnss.so.1.0", ["nss"]),
            ("libtiff", "libtiff.so.1.0", ["tiff"]),
            ("lighttpd", "lighttpd", ["lighttpd"]),
            ("ncurses", "libform", ["ncurses"]),
            ("nessus", "libnessus", ["nessus"]),
            ("nginx", "nginx", ["nginx"]),
            ("node", "bin/node", ["node"]),
            ("openssh_client", "scp", ["openssh-client"]),
            ("openssh_client", "sftp", ["openssh-client"]),
            ("openssh_client", "ssh", ["openssh-client"]),
            ("openssh_client", "ssh-add", ["openssh-client"]),
            ("openssh_client", "ssh-agent", ["openssh-client"]),
            ("openssh_client", "ssh-argv0", ["openssh-client"]),
            ("openssh_client", "ssh-copy-id", ["openssh-client"]),
            ("openssh_client", "ssh-keygen", ["openssh-client"]),
            ("openssh_client", "ssh-keyscan", ["openssh-client"]),
            ("openssh_client", "slogin", ["openssh-client"]),
            ("openssh_server", "sshd", ["openssh-server"]),
            ("openssl", "libcrypto.so", ["openssl"]),
            ("openswan", "ranbits.so", ["openswan"]),
            ("png", "libpng.so.1.0", ["png"]),
            ("postgresql", "psql", ["postgresql"]),
            ("python", "python", ["python"]),
            ("python", "python2.7", ["python"]),
            ("python", "python3.8", ["python"]),
            ("python", "python3.9", ["python"]),
            ("rsyslog", "rsyslogd.so", ["rsyslog"]),
            ("sqlite", "sqlite3", ["sqlite"]),
            ("strongswan", "libcharon.so", ["strongswan"]),
            ("syslogng", "syslog-ng.so", ["syslog-ng"]),
            ("systemd", "libsystemd.so.0", ["systemd"]),
            ("varnish", "varnish", ["varnish"]),
            ("wireshark", "rawshark", ["wireshark"]),
            ("xerces", "libxerces-c.so", ["xerces"]),
            ("xml2", "libxml2.so.0", ["xml2"]),
            ("zlib", "libz.so.0", ["zlib"]),
        ],
    )
    def test_filename_is(self, checker_name, file_name, expected_results):
        """Test a checker's filename detection"""
        checkers = pkg_resources.iter_entry_points("cve_bin_tool.checker")
        for checker in checkers:
            if checker.name == checker_name:
                Checker = checker.load()
                checker = Checker()

                result = checker.get_version([""], file_name)

                if "is_or_contains" in result:
                    results = [dict()]
                    results[0] = result
                else:
                    results = result

                for result, expected_result in zip(results, expected_results):
                    assert result["is_or_contains"] == "is"

    def test_glibc_latest_version(self):
        """Checker didn't detect latest version of glibc"""

        common_versions = [
            # common strings generated by a compiler
            r"$Pj?PW\n"
            r"D$ P\n"
            r"D$0PW\n"
            r"GNU C Library (GNU libc) release release version\n",
            r"Mandatory or optional arguments to long options are also mandatory or optional for any corresponding short options.\n",
            r"Compiled by GNU CC version 10.2.1 20200804 (Red Hat 10.2.1-2).\n",
            # bare version strings.
            r"GLIBC_2.0\n",
            r"GLIBC_2.1\n",
            r"GLIBC_2.1.1\n",
            r"GLIBC_2.3\n",
            r"GLIBC_2.3.2\n",
            r"GLIBC_2.12\n",
            r"GLIBC_2.23\n",
            r"GLIBC_2.30\n",
            r"GLIBC_2.32\n",
        ]
        versions_not_considered = [
            "2.0",
            "2.1",
            "2.1.1",
            "2.3.2",
            "2.12",
            "2.23",
            "2.30",
        ]
        file_name = "libc.so.6"
        checkers = pkg_resources.iter_entry_points("cve_bin_tool.checker")
        result = None
        for checker in checkers:
            if checker.name == "glibc":
                Checker = checker.load()
                checker = Checker()

                result = checker.get_version(common_versions, file_name)

        if "is_or_contains" in result:
            assert result["version"] not in versions_not_considered
