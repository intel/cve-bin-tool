# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool Format Checker tests
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

import cve_bin_tool.format_checkers as format_checkers


class TestFormatCheckers:
    """Tests the CVE Bin Tool Format Checkers Script"""

    @classmethod
    def setup_class(cls):
        cls.mock_path_dir = Path(__file__).parent / "format_checkers"
        cls.mock_checkers = [
            "libssh2",
            "polarssl_fedora",
            "radare2",
            "rsyslog",
            "open_vm_tools",
            "libssh2",
            "polarssl_fedora",
            "busybox",
            "commons_compress",
            "bzip2",
        ]
        cls.mock_checkers.sort()

    @pytest.mark.asyncio
    async def test_update_allowed_words(self, mocker: MockerFixture):
        """Tests the update_allowed_words function"""
        file_path = self.mock_path_dir / "allow.txt"

        mocked_file = mocker.patch(
            "cve_bin_tool.format_checkers.open", mocker.mock_open()
        )
        format_checkers.update_allowed_words(
            checkers_array=self.mock_checkers, file_path=file_path
        )

        words = re.findall(r"[^0-9_]+", "_".join(self.mock_checkers))
        words = list(set(words))
        words = sorted(words, key=str.casefold)

        # assert if opened file twice, once in read mode 'r' and once in write mode 'w'
        mocked_file.assert_has_calls(
            [mocker.call(file_path), mocker.call(file_path, "w+")],
            any_order=True,
        )

        # assert if writelines was called from the file opened
        mocked_file().writelines.assert_called_once_with("\n".join(words) + "\n\n")

    @pytest.fixture
    def checkers_array(self):
        checkers_array = format_checkers.reshape_list(self.mock_checkers)
        assert (len(checkers_array) == 2) & (
            [len(checkers_array[0]), len(checkers_array[1])] == [7, 3]
        )
        return checkers_array

    @pytest.fixture
    def shape_list(self, checkers_array: list[list[str]]):
        shape_list = format_checkers.max_checker_length(checkers_array)
        assert shape_list == [15, 7, 16, 7, 7, 13, 15]
        return shape_list

    @pytest.fixture
    def checkers_markdown(self, checkers_array: list[list[str]], shape_list: list[int]):
        checkers_markdown = format_checkers.reformat_checkers(
            checkers_array, shape_list
        )
        return checkers_markdown

    def test_reformat_checkers(self, checkers_markdown, mocker: MockerFixture):
        """Tests the reformat_checkers function"""

        file_path = self.mock_path_dir / "checkers.md"

        mocked_file = mocker.patch(
            "cve_bin_tool.format_checkers.open",
            mocker.mock_open(
                read_data="\n<!-- CHECKERS TABLE BEGIN -->\n<!-- CHECKERS TABLE END -->"
            ),
        )

        format_checkers.update_checker_table(
            file_path=file_path,
            markdown=checkers_markdown,
        )
        mocked_file().writelines.assert_called_once_with(
            [
                "\n",
                "<!-- CHECKERS TABLE BEGIN -->\n",
                checkers_markdown,
                "<!-- CHECKERS TABLE END -->",
            ]
        )
