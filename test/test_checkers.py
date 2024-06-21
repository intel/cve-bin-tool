# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import re

import pytest

from cve_bin_tool.checkers import BUILTIN_CHECKERS, Checker, VendorProductPair
from cve_bin_tool.egg_updater import IS_DEVELOP, update_egg
from cve_bin_tool.log import LOGGER

Pattern = type(re.compile("", 0))


class TestCheckerClass:
    def test_valid_checker(self):
        class MyChecker(Checker):
            CONTAINS_PATTERNS = [r"look"]
            VERSION_PATTERNS = [r"for"]
            FILENAME_PATTERNS = [r"myproduct"]
            VENDOR_PRODUCT = [("myvendor", "myproduct")]
            IGNORE_PATTERNS = [r"ignore"]

        assert type(MyChecker.CONTAINS_PATTERNS[0]) is Pattern
        assert type(MyChecker.VERSION_PATTERNS[0]) is Pattern
        assert type(MyChecker.FILENAME_PATTERNS[0]) is Pattern
        assert type(MyChecker.VENDOR_PRODUCT[0]) is VendorProductPair
        assert type(MyChecker.IGNORE_PATTERNS[0]) is Pattern

    def test_no_vpkg(self):
        with pytest.raises(AssertionError) as e:

            class MyChecker(Checker):
                CONTAINS_PATTERNS = [r"look"]
                VERSION_PATTERNS = [r"for"]
                FILENAME_PATTERNS = [r"myproduct"]
                PRODUCT_NAME = "mychecker"
                IGNORE_PATTERNS = [r"ignore"]

        assert e.value.args[0] == "MyChecker needs at least one vendor product pair"


class TestCheckerVersionParser:
    """Run a series of tests directly against individual checkers.
    This is a companion to the tests in TestScanner."""

    @classmethod
    def setup_class(cls):
        """Initialize egg so all checkers can be found"""
        # Update egg if installed in development mode
        if IS_DEVELOP():
            LOGGER.info("Updating egg_info")
            update_egg()

    @pytest.mark.parametrize(
        "checker_name, file_name, expected_results",
        [
            ("apache", "httpd", ["apache"]),
            ("binutils", "dlltool", ["binutils"]),
            ("bzip2", "bzip2.so", ["bzip2"]),
            ("cups", "cupsd.so", ["cups"]),
            ("curl", "libcurl.so.4", ["curl"]),
            ("emacs", "emacs", ["emacs"]),
            ("emacs", "emacs-nox", ["emacs"]),
            ("emacs", "emacs-gtk", ["emacs"]),
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
            ("kerberos", "kerberos", ["kerberos_5"]),
            ("libcurl", "libcurl.so.2.0", ["libcurl"]),
            ("libdb", "libdb-2.0.so", ["libdb"]),
            ("libexpat", "libexpat.so", ["libexpat"]),
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
            ("vim", "vim", ["vim"]),
            ("vim", "vim-enhanced", ["vim"]),
            ("wireshark", "rawshark", ["wireshark"]),
            ("xerces", "libxerces-c.so", ["xerces"]),
            ("xml2", "libxml2.so.0", ["xml2"]),
            ("zlib", "libz.so.0", ["zlib"]),
            ("bind", "libbind9-9.16.37-Debian.so", ["bind"]),
            ("bind", "libdns-9.16.37-Debian.so", ["bind"]),
            ("bind", "libirs-9.16.37-Debian.so", ["bind"]),
            ("bind", "libisc-9.16.37-Debian.so", ["bind"]),
            ("bind", "libisccc-9.16.37-Debian.so", ["bind"]),
            ("bind", "libisccfg-9.16.37-Debian.so", ["bind"]),
            ("bind", "libns-9.16.37-Debian.so", ["bind"]),
        ],
    )
    def test_filename_is(self, checker_name, file_name, expected_results):
        """Test a checker's filename detection"""
        for checker in BUILTIN_CHECKERS.values():
            if checker.name == checker_name:
                Checker = checker.load()
                checker = Checker()

                result = checker.get_version("", file_name)

                if "is_or_contains" in result:
                    results = [dict()]
                    results[0] = result
                else:
                    results = result

                for result, expected_result in zip(results, expected_results):
                    assert result["is_or_contains"] == "is"

    class MyFakeChecker(Checker):
        CONTAINS_PATTERNS: list[str] = []
        FILENAME_PATTERNS: list[str] = [r"checker"]
        VERSION_PATTERNS = [r"mychecker-([0-9].[0-9]+)"]
        VENDOR_PRODUCT = [("my", "checker")]
        IGNORE_PATTERNS = [r"mychecker-5.6"]

    string = "Some other lines. \n Ignore this version pattern mychecker-5.6. \n Consider this version pattern mychecker-5.8. \n Some more lines."
    lines = string.split("\n")
    checker = MyFakeChecker()

    result1 = checker.get_version(lines[1], "")
    assert result1["version"] == "UNKNOWN"

    result2 = checker.get_version(lines[2], "")
    assert result2["version"] == "5.8"
