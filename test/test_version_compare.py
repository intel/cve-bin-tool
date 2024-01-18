# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

from cve_bin_tool.version_compare import UnknownVersion, Version


class TestVersionCompare:
    """Test the cve_bin_tool.version_compare functionality"""

    def test_eq(self):
        """Make sure == works between versions"""
        assert Version("1.2") == Version("1.2")
        assert Version("1.1a") == Version("1.1A")
        assert Version("4.4.A") == Version("4.4.a")
        assert Version("5.6   ") == Version("5.6")
        assert Version("f835f2caaa") == Version("f835f2caaa")

    def test_lt(self):
        """Make sure < works between versions, including some with unusual version schemes"""
        assert Version("1.2") < Version("1.3")
        assert Version("1.2a") < Version("1.3")
        assert Version("1_2a") < Version("5a")
        assert Version("5.6.dev1") < Version("5.6")
        assert Version("5.6.dev1") < Version("5.6.dev2")
        assert Version("5.4") < Version("5.4.1")
        assert Version("5.4.dev5") < Version("5.4.1")
        assert Version("1.2.pre4") < Version("1.2.1")
        assert Version("1.2.post8") < Version("1.2.1")
        assert Version("rc5") < Version("rc10")
        assert Version("9.10") < Version("9.10.post")
        assert Version("5.3.9") < Version("5.4")
        assert Version("2.0.0") < Version("2.0.0-1+deb9u1")
        assert Version("0.0.0.20190813141303.74dc4d7220e7") < Version(
            "0.0.0.20200813141303"
        )
        assert Version("1.1.0l.1~deb9u2") < Version("2.0.0-1+deb9u1")
        assert Version("1.1.0l.1~deb9u2") < Version("1.1.0m")
        assert Version("8.9~deb7u9") < Version("8.9~deb9u6")
        assert Version("8.9~deb7u9") < Version("8.9~deb9u6")
        assert Version("3.9.pre1") < Version("3.9.u")
        assert Version("3.9.rc1") < Version("3.9.g")
        assert Version("pre4") < Version("3")

    def test_gt(self):
        """Make sure > works between versions, including some with unusual version schemes"""
        assert Version("1.1.1a") > Version("1.0.1z")
        assert Version("2-kdc") > Version("2-a")
        assert Version("7.34.0") > Version("7.3.0")
        assert Version("5.6.1") > Version("5.6.dev2")
        assert Version("5.4.6") > Version("5.4")
        assert Version("10.2.3.rc1") > Version("10.2.3.rc0")
        assert Version("10.2.3.rc10") > Version("10.2.3.rc2")
        assert Version("9.10.post") > Version("9.10")
        assert Version("5.5") > Version("5.4.1")
        assert Version("2.0.0-1+deb9u1") > Version("2.0.0")
        assert Version("0.0.0.20200813141303") > Version(
            "0.0.0.20190813141303.74dc4d7220e7"
        )
        assert Version("1.1.0m") > Version("1.1.0l.1~deb9u2")
        assert Version("8.9~deb9u6") > Version("8.9~deb7u9")
        assert Version("3.9.u") > Version("3.9.pre1")
        assert Version("3.9.g") > Version("3.9.rc1")
        assert Version("2") > Version("pre3")

    def test_error(self):
        """Make sure 'unknown' and blank strings raise appropriate errors"""
        with pytest.raises(UnknownVersion):
            Version("6") > Version("unknown")
        with pytest.raises(UnknownVersion):
            Version("") > Version("6")

    def test_ne(self):
        """Test some != cases with hashes to make sure we aren't comparing the string 'HASH'"""
        assert Version("f835f2caab") != Version("f835f2caaa")
        assert Version("HASH") != Version("f835f2caaa")
