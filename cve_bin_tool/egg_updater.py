# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import os
import sys
from io import StringIO

from setuptools import Distribution, find_packages

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
        sys.stdout = f
        sys.stderr = f
        dist = Distribution(
            dict(
                script_name="setup.py",
                script_args=["egg_info"],
                name="cve-bin-tool",
                version=VERSION,
                packages=find_packages(
                    exclude=["locales", "presentation"],
                ),
                entry_points={
                    "console_scripts": [
                        "cve-bin-tool = cve_bin_tool.cli:main",
                        "csv2cve = cve_bin_tool.csv2cve:main",
                    ],
                    "cve_bin_tool.checker": [
                        "{} = cve_bin_tool.checkers.{}:{}".format(
                            filename.replace(".py", ""),
                            filename.replace(".py", ""),
                            "".join(
                                (filename.replace(".py", "") + " checker")
                                .replace("_", " ")
                                .title()
                                .split()
                            ),
                        )
                        for filename in os.listdir(
                            os.path.join(
                                os.path.abspath(os.path.dirname(__file__)),
                                "checkers",
                            )
                        )
                        if filename.endswith(".py") and "__init__" not in filename
                    ],
                },
            )
        )
        dist.parse_command_line()
        dist.run_commands()
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        os.chdir(cwd)


if __name__ == "__main__":
    update_egg()
