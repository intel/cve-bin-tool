# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import dataclasses
import pathlib
import re

from packageurl import PackageURL

from cve_bin_tool.parsers import Parser
from cve_bin_tool.util import ProductInfo, ScanInfo


@dataclasses.dataclass
class EnvNamespaceConfig:
    ad_hoc_cve_id: str
    vendor: str
    product: str
    version: str
    location: str = "/usr/local/bin/product"


@dataclasses.dataclass
class EnvConfig:
    namespaces: dict[str, EnvNamespaceConfig]


class EnvParser(Parser):
    """
    Parser for Python requirements files.
    This parser is designed to parse Python requirements files (usually named
    requirements.txt) and generate PURLs (Package URLs) for the listed packages.
    """

    PARSER_MATCH_FILENAMES = [
        ".env",
    ]

    @staticmethod
    def parse_file_contents(contents):
        lines = list(
            [
                line
                for line in contents.replace("\r\n", "\n").split("\n")
                if line.strip() and line.startswith("CVE_BIN_TOOL_")
            ]
        )
        namespaces = {}
        for i, line in enumerate(lines):
            key, value = line.split("=", maxsplit=1)
            namespace, key = key[len("CVE_BIN_TOOL_") :].split("_", maxsplit=1)
            if value.startswith('"'):
                value = value[1:]
            if value.endswith('"'):
                value = value[:-1]
            namespaces.setdefault(namespace, {})
            namespaces[namespace][key.lower()] = value
        for namespace, config in namespaces.items():
            namespaces[namespace] = EnvNamespaceConfig(**config)
        return EnvConfig(namespaces=namespaces)

    def run_checker(self, filename):
        """
        Parse the .env file and yield ScanInfo objects for the listed packages.
        Args:
            filename (str): The path to the .env file.
        Yields:
            str: ScanInfo objects for the packages listed in the file.
        """
        self.filename = filename
        contents = pathlib.Path(self.filename).read_text()

        env_config = self.parse_file_contents(contents)

        data_source = "environment"
        affected_data = [
            {
                "cve_id": cve.ad_hoc_cve_id,
                "vendor": cve.vendor,
                "product": cve.product,
                # TODO Version MUST be unique to this bug!
                "version": cve.version,
                "versionStartIncluding": "",
                # "versionStartIncluding": cve.version,
                "versionStartExcluding": "",
                "versionEndIncluding": "",
                # "versionEndIncluding": cve.version,
                "versionEndExcluding": "",
            }
            for _namespace, cve in env_config.namespaces.items()
        ]
        severity_data = [
            {
                "ID": cve.ad_hoc_cve_id,
                # TODO severity
                "severity": "LOW",
                # TODO description
                "description": "TODO",
                # TODO score
                "score": 0,
                # TODO CVSS_version
                "CVSS_version": 3,
                # TODO CVSS_vector
                "CVSS_vector": "",
                "last_modified": "",
            }
            for _namespace, cve in env_config.namespaces.items()
        ]

        with self.cve_db.with_cursor() as cursor:
            self.cve_db.populate_cve_metrics(severity_data, cursor)
            self.cve_db.populate_severity(severity_data, cursor, data_source)
            self.cve_db.populate_affected(affected_data, cursor, data_source)

        for _namespace, cve in env_config.namespaces.items():
            yield ScanInfo(
                ProductInfo(
                    cve.vendor,
                    cve.product,
                    cve.version,
                    cve.location,
                    PackageURL(
                        type="ad-hoc",
                        namespace=cve.vendor,
                        name=re.sub(r"[^a-zA-Z0-9._-]", "", cve.product).lower(),
                        version=cve.version,
                        qualifiers={},
                        subpath=None,
                    ),
                ),
                pathlib.Path(filename).resolve(),
            )
