# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import textwrap

import requests
from packaging import version

from cve_bin_tool.log import LOGGER

VERSION: str = "3.3rc2"

HTTP_HEADERS: dict = {
    "User-Agent": f"cve-bin-tool/{VERSION} (https://github.com/intel/cve-bin-tool/)",
}


def check_latest_version():
    """Checks for the latest version available at PyPI."""

    name: str = "cve-bin-tool"
    url: str = f"https://pypi.org/pypi/{name}/json"
    try:
        package_json = requests.get(url, timeout=300).json()
        pypi_version = package_json["info"]["version"]
        if pypi_version != VERSION:
            LOGGER.info(
                f"[bold red]You are running version {VERSION} of {name} but the latest PyPI Version is {pypi_version}.[/]",
                extra={"markup": True},
            )
            if version.parse(VERSION) < version.parse(pypi_version):
                LOGGER.info(
                    "[bold yellow]Alert: We recommend using the latest stable release.[/]",
                    extra={"markup": True},
                )
    except Exception as error:
        LOGGER.warning(
            textwrap.dedent(
                f"""
        -------------------------- Can't check for the latest version ---------------------------
        warning: unable to access 'https://pypi.org/pypi/{name}'
        Exception details: {error}
        Please make sure you have a working internet connection or try again later.
        """
            )
        )
