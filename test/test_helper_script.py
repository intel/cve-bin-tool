# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from re import UNICODE

import pytest

from cve_bin_tool.error_handler import UnknownArchiveType
from cve_bin_tool.helper_script import HelperScript


class TestHelperScript:
    @pytest.mark.parametrize(
        "filename, product_name",
        [
            (
                "libsndfile-1.0.25-12.el7.x86_64.rpm",
                "libsndfile",
            ),  # normal packages (with 2 '-')
            (
                "libsndfile-1.0.31-1-aarch64.pkg.tar.xz",
                "libsndfile",
            ),  # .tar.xz packages (with 3 '-')
            (
                "logrotate_3.14.0-4ubuntu5_amd64.deb",
                "logrotate",
            ),  # .deb packages (with 2 '_')
            (
                "libarchive_3.4.2-1_aarch64_cortex-a72.ipk",
                "libarchive",
            ),  # .ipk packages (with 3 '_')
            (
                "tomcat9_9.0.37-3_all.deb",
                "tomcat9",
            ),  # packages with digits in product_name
            (
                "openssh-client_8.4p1-5ubuntu1_amd64.deb",
                "openssh-client",
            ),  # packages with '-' in product_name
            (
                "./Packages/bash-4.2.46-34.el7.x86_64.rpm",
                "bash",
            ),  # directaory names
        ],
    )
    def test_parse_filename(self, filename, product_name):
        hs = HelperScript(filename)
        assert hs.parse_filename(filename) == product_name

    # @pytest.mark.parametrize("filename", [
    #     "bash-4.2.46-34.el7.x86_64.abc" # unsupported file type
    # ])
    # def test_parse_filename(self, filename):
    #     hs = HelperScript(filename)
    #     with pytest.raises(UnknownArchiveType):
    #         hs.parse_filename(filename)
