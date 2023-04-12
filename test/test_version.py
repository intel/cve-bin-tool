# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import re
import textwrap

import pytest
from pytest_mock import MockerFixture

from cve_bin_tool.version import VERSION, check_latest_version


class TestVersion:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("version_jump", (-1, 1))
    async def test_different_version(
        self, version_jump: int, caplog, mocker: MockerFixture
    ):
        name: str = "cve-bin-tool"

        # Reducing the version number
        _versions = VERSION.split(".")
        _versions[0] = str(int(_versions[0]) + version_jump)
        _version = ".".join(_versions)

        # Mocking the get function to return _version
        mock_json = {"info": {"version": _version}}
        mock_get = mocker.patch("requests.get")
        mock_get.return_value.json.return_value = mock_json

        check_latest_version()

        # Asserting if the get request was made succesfully
        mock_get.assert_called_once_with(
            f"https://pypi.org/pypi/{name}/json", timeout=300
        )
        assert (
            "cve_bin_tool",
            logging.INFO,
            f"[bold red]You are running version {VERSION} of {name} but the latest PyPI Version is {_version}.[/]",
        ) in caplog.record_tuples

        if version_jump > 0:
            assert (
                "cve_bin_tool",
                logging.INFO,
                "[bold yellow]Alert: We recommend using the latest stable release.[/]",
            ) in caplog.record_tuples

    @pytest.mark.asyncio
    async def test_exception(
        self, caplog: pytest.LogCaptureFixture, mocker: MockerFixture
    ) -> None:
        mocker.patch("requests.get", sideEffect=Exception())

        check_latest_version()

        assert any(
            True
            for logger_name, logger_level, message in caplog.record_tuples
            if logger_name == "cve_bin_tool"
            and logger_level == logging.WARNING
            and re.match(
                textwrap.dedent(
                    """
        -------------------------- Can't check for the latest version ---------------------------
        warning: unable to access 'https://pypi.org/pypi/cve-bin-tool'
        Exception details: expected string or bytes-like object(?:.*)
        Please make sure you have a working internet connection or try again later.
        """
                ),
                message,
            )
        )
