# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

import pytest

from cve_bin_tool.config import ConfigParser
from cve_bin_tool.error_handler import ErrorMode, UnknownConfigType


class TestConfig:
    TEST_PATH = Path(__file__).parent.resolve()
    EXPECTED_CONFIG = {
        "cvss": 0,
        "directory": "test/assets",
        "disable_version_check": False,
        "extract": True,
        "format": "console",
        "input_file": "test/csv/triage.csv",
        "log_level": "debug",
        "output_file": "",
        "quiet": False,
        "runs": ["libcurl", "binutils"],
        "severity": "low",
        "skips": ["python", "bzip2"],
        "update": "daily",
    }

    def test_non_existent_config(self):
        config_parser = ConfigParser("config.toml", error_mode=ErrorMode.FullTrace)
        with pytest.raises(FileNotFoundError):
            config_parser.parse_config()

    def test_unsupported_config(self):
        config_parser = ConfigParser(
            str(self.TEST_PATH / "json" / "bad.json"),
            error_mode=ErrorMode.FullTrace,
        )
        with pytest.raises(UnknownConfigType):
            config_parser.parse_config()

    @pytest.mark.parametrize(
        "filepath, expected_config",
        (
            (
                str(TEST_PATH / "config" / "cve_bin_tool_config.toml"),
                EXPECTED_CONFIG,
            ),
            (
                str(TEST_PATH / "config" / "cve_bin_tool_config.yaml"),
                EXPECTED_CONFIG,
            ),
        ),
    )
    def test_valid_config(self, filepath, expected_config):
        config_parser = ConfigParser(filepath)
        assert dict(config_parser.parse_config()) == expected_config
