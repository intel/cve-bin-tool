import sys
import ast
import os
from io import open
from setuptools import find_packages, setup, Extension

with open("README.md", "r", encoding="utf-8") as f:
    readme = f.read()

setup_kwargs = dict(
    name="cve-bin-tool",
    version="0.3.0",
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
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    install_requires=["jsonschema>=3.0.2"],
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "cve-bin-tool = cve_bin_tool.cli:main",
            "csv2cve = cve_bin_tool.csv2cve:main",
        ],
        "cve_bin_tool.checker": [
            "%s = cve_bin_tool.checkers.%s:get_version"
            % tuple((2 * [filename.replace(".py", "")]))
            for filename in os.listdir(
                os.path.join(
                    os.path.abspath(os.path.dirname(__file__)),
                    "cve_bin_tool",
                    "checkers",
                )
            )
            if filename[::-1].startswith("yp.") and not "__init__" in filename
        ],
    },
)

if sys.version_info.major == 3:
    setup_kwargs["ext_modules"] = [
        Extension("cve_bin_tool.pstring", [os.path.join("cve_bin_tool", "string.c")])
    ]

setup(**setup_kwargs)
