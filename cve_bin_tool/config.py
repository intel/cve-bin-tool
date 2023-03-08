# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from collections import ChainMap
from logging import Logger
from pathlib import Path
from typing import Mapping

import toml
import yaml

from cve_bin_tool.error_handler import ErrorHandler, ErrorMode, UnknownConfigType
from cve_bin_tool.log import LOGGER


class ConfigParser:
    # Key-value pair of config data ex: {"extract": True, "directory": "test/assets"}
    config_data: Mapping[str, dict[str, dict[str, str | bool | int | list[str]]]]

    def __init__(
        self,
        filename: str,
        logger: Logger | None = None,
        error_mode=ErrorMode.TruncTrace,
    ):
        self.filename = str(Path(filename).resolve())
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.error_mode = error_mode
        self.config_data = {}

    def parse_config(
        self,
    ) -> Mapping[str, dict[str, dict[str, str | bool | int | list[str]]]]:
        if not Path(self.filename).is_file():
            with ErrorHandler(mode=self.error_mode):
                raise FileNotFoundError(self.filename)
        if self.filename.endswith(".toml"):
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
