# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import os
import pathlib

from setuptools import find_packages, setup

PACKAGE_ROOT_PATH = pathlib.Path(__file__).parent.resolve()

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
    license="GPL-3.0-or-later",
    keywords=["security", "tools", "CVE"],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    install_requires=requirements,
    extras_require={
        "PDF": ["reportlab"],
    },
    packages=find_packages(
        exclude=["locales", "presentation"],
    ),
    package_data={
        "cve_bin_tool.output_engine": [
            "html_reports/templates/*.html",
            "html_reports/css/*.css",
            "html_reports/js/*.js",
            "print_mode/templates/*.html",
        ],
        "cve_bin_tool": [
            "schemas/*.xsd",
        ],
        "sbom": ["*.spdx", "*.json"],
    },
    entry_points={
        "console_scripts": [
            "cve-bin-tool = cve_bin_tool.cli:main",
            "csv2cve = cve_bin_tool.csv2cve:main",
            "mismatch = mismatch.cli:main",
        ],
    },
)

if __name__ == "__main__":
    setup(**setup_kwargs)
