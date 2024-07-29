# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import importlib.util
import os
import sys
from io import StringIO

from setuptools import Distribution

try:
    from cve_bin_tool.version import VERSION
except ModuleNotFoundError:
    with open(os.path.join("cve_bin_tool", "version.py")) as f:
        for line in f:
            if line.startswith("VERSION"):
                VERSION = ast.literal_eval(line.strip().split("=")[-1].strip())
                break


def IS_DEVELOP() -> bool:
    """
    Check if any of the paths in sys.path contain a file named 'cve-bin-tool.egg-link'.

    Returns:
        bool: True if at least one 'cve-bin-tool.egg-link' file exists in any of the directories
              listed in sys.path, False otherwise.
    """

    return any(
        list(
            map(
                os.path.isfile,
                list(
                    map(
                        lambda syspath: os.path.join(syspath, "cve-bin-tool.egg-link"),
                        sys.path,
                    )
                ),
            )
        )
    )


def update_egg() -> None:
    """
    Update the egg-info(metadata directory) for the 'cve-bin-tool' package.

    This function updates the egg information for the 'cve-bin-tool' package
    by running the 'egg_info' command using the 'setup.py' script.

    Raises:
        None

    Returns:
        None
    """

    with StringIO() as f:
        cwd = os.getcwd()
        os.chdir(os.path.join(os.path.dirname(__file__), ".."))
        setup_spec = importlib.util.spec_from_file_location(
            "setup", os.path.join(os.path.dirname(__file__), "..", "setup.py")
        )
        setup_module = importlib.util.module_from_spec(setup_spec)
        setup_spec.loader.exec_module(setup_module)
        setup_kwargs = setup_module.setup_kwargs
        sys.stdout = f
        sys.stderr = f
        setup_kwargs.update(
            dict(
                script_name="setup.py",
                script_args=["egg_info"],
            )
        )
        dist = Distribution(setup_kwargs)
        dist.parse_command_line()
        dist.run_commands()
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        os.chdir(cwd)


if __name__ == "__main__":
    update_egg()
