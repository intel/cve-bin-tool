# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from setuptools import setup

setup(
    name="oot-checker",
    version="0.0.1",
    description="",
    long_description="Out of tree checker for CVE Bin Tool",
    author="CVE Bin Tool",
    author_email="cve.bin.tool@intel.com",
    url="https://github.com/intel/cve-bin-tool",
    license="GPLv3",
    keywords=[""],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    # Dependencies got here aka install_requires=['tensorflow']
    install_requires=[],
    tests_require=[],
    entry_points={
        "cve_bin_tool.checker": ["checker_name = oot_checker.checker_name:CurlChecker"]
    },
)
