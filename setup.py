# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import os

from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as f:
    readme = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    requirements = f.read().split("\n")

with open(os.path.join("cve_bin_tool", "version.py")) as f:
    for line in f:
        if line.startswith("VERSION"):
            VERSION = ast.literal_eval(line.strip().split("=")[-1].strip())
            break

setup_kwargs = dict(
    name="cve-bin-tool",
    version=VERSION,
    description="CVE Binary Checker Tool",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="Terri Oda",
    author_email="terri.oda@intel.com",
    maintainer="Terri Oda",
    maintainer_email="terri.oda@intel.com",
    url="https://github.com/intel/cve-bin-tool",
    license="GPLv3",
    keywords=["security", "tools", "CVE"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    install_requires=requirements,
    packages=find_packages(),
    package_data={
        "cve_bin_tool.output_engine": [
            "html_reports/templates/*.html",
            "html_reports/css/*.css",
            "html_reports/js/*.js",
            "print_mode/templates/*.html",
        ]
    },
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
                    "cve_bin_tool",
                    "checkers",
                )
            )
            if filename.endswith(".py") and "__init__" not in filename
        ],
    },
)

setup(**setup_kwargs)
