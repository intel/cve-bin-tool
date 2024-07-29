# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import sys
from collections import ChainMap
from logging import Logger
from pathlib import Path
from typing import Mapping

if sys.version_info >= (3, 11):
    import tomllib as toml
else:
    import toml

import yaml

from cve_bin_tool.error_handler import ErrorHandler, ErrorMode, UnknownConfigType
from cve_bin_tool.log import LOGGER


class ConfigParser:
    """
    Parses configuration files in either TOML or YAML format.
    """

    config_data: Mapping[str, dict[str, dict[str, str | bool | int | list[str]]]]

    # Key-value pairs of config data, e.g., {"extract": True, "directory": "test/assets"}.

    def __init__(
        self,
        filename: str,
        logger: Logger | None = None,
        error_mode=ErrorMode.TruncTrace,
    ):
        """
        Initializes the ConfigParser instance.

        Args:
            filename (str): The path to the configuration file.
            logger (Logger, optional): The logger instance for logging messages.
            error_mode (ErrorMode, optional): The mode for error handling during parsing.
        """
        self.filename = str(Path(filename).resolve())
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.error_mode = error_mode
        self.config_data = {}

    def parse_config(
        self,
    ) -> Mapping[str, dict[str, dict[str, str | bool | int | list[str]]]]:
        """
        Parses the configuration file and returns the config data.

        Returns:
            Mapping[str, dict[str, dict[str, str | bool | int | list[str]]]]:
                Key-value pairs of config data.
        Raises:
            FileNotFoundError: If the specified file is not found.
            UnknownConfigType: If the file has an unsupported configuration type.
        """
        if not Path(self.filename).is_file():
            with ErrorHandler(mode=self.error_mode):
                raise FileNotFoundError(self.filename)
        if self.filename.endswith(".toml"):
            if sys.version_info >= (3, 11):
                with open(self.filename, "rb") as f:
                    raw_config_data = toml.load(f)
            else:
                with open(self.filename) as f:
                    raw_config_data = toml.load(f)
            self.config_data = ChainMap(*raw_config_data.values())
        elif self.filename.endswith(".yaml"):
            with open(self.filename) as f:
                raw_config_data = yaml.safe_load(f)
                self.config_data = ChainMap(*raw_config_data.values())
        else:
            with ErrorHandler(mode=self.error_mode):
                raise UnknownConfigType(
                    f"config file: {self.filename} is not supported."
                )
        return self.config_data
