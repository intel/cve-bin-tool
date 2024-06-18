# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import re
import subprocess
import sys
import uuid

import yaml
from packageurl import PackageURL

from cve_bin_tool.parsers import Parser
from cve_bin_tool.util import ProductInfo, ScanInfo


@dataclasses.dataclass
class BanditNamespaceConfig:
    ad_hoc_cve_id: str
    vendor: str
    product: str
    version: str
    location: str
    description: str
    severity: str
    score: float


@dataclasses.dataclass
class BanditConfig:
    namespaces: dict[str, BanditNamespaceConfig]


class BanditParser(Parser):
    """
    Parser for Python requirements files.
    This parser is designed to parse Python requirements files (usually named
    requirements.txt) and generate PURLs (Package URLs) for the listed packages.
    """

    PARSER_MATCH_FILENAMES = [
        ".py",
    ]

    @staticmethod
    def parse_bandit_output(filename, contents):
        username = os.environ.get("USER", "unknown-user")
        config_gh_hosts_yaml_path = pathlib.Path(
            "~", ".config", "gh", "hosts.yml"
        ).expanduser()
        if config_gh_hosts_yaml_path.exists():
            # GitHub username if gh CLI installed
            config_gh_hosts_yaml = yaml.safe_load(config_gh_hosts_yaml_path.read_text())
            platform = "github.com"
            username = config_gh_hosts_yaml[platform]["user"]
        vendor = f"username:{username}:platform:{platform}"
        product = f"filepath:{filename}"
        version = f"v0.0.0.dev-SomeShaValue-N-Other-Branches-Workload-ID-Scan-Number-{uuid.uuid4()}"

        contents = json.loads(contents)

        errors = contents.get("errors", [])
        if errors:
            raise Exception(json.dumps(contents))

        namespaces = {}
        for i, result in enumerate(contents.get("results", [])):
            # Version is the same when code at location matches code from output
            result["issue_text"]
            result["code"]

            # TODO Replace UUID with with SCITT URN
            # SCITT A.4.2
            ad_hoc_cve_id = f"CVE-0001-urn:ietf:params:scitt:statement:sha-256:base64url:5i6UeRzg1...{i}...qnGmr1o"

            # TODO Sort by something, line? Int of content address?
            namespace = f"bandit-{i}"

            # TODO Take vendor product and version automatically from git repo
            # or installed pypi package meta-info.
            namespaces[namespace] = BanditNamespaceConfig(
                ad_hoc_cve_id=ad_hoc_cve_id,
                vendor=vendor,
                product=product,
                version=version,
                severity="LOW",
                score=0.0,
                location=result["line_number"],
                description=json.dumps(result),
            )
        return BanditConfig(namespaces=namespaces)

    def run_checker(self, filename):
        """
        Parse the .bandit file and yield ScanInfo objects for the listed packages.
        Args:
            filename (str): The path to the .bandit file.
        Yields:
            str: ScanInfo objects for the packages listed in the file.
        """
        file_path = pathlib.Path(filename).resolve()
        cmd = [
            sys.executable,
            "-um",
            "bandit",
            "-f",
            "json",
            "--exit-zero",
            "--",
            # TODO Relative paths? Need top level directory being scanned
            str(file_path),
        ]
        try:
            stdout = subprocess.check_output(
                cmd,
            )
        except subprocess.CalledProcessError as error:
            raise Exception(error.stderr) from error

        bandit_config = self.parse_bandit_output(filename, stdout)

        # TODO Create SCITT_URN_FOR_MANIFEST_OF_EXECUTED_WORKFLOW_WITH_SARIF_OUTPUTS_DEREFERENCEABLE
        # by making a request to the poligy engine and getting it's workflow
        # manifest as output and deriving from that or extend it to return that.
        data_source = "SCITT_URN_FOR_MANIFEST_OF_EXECUTED_WORKFLOW_WITH_SARIF_OUTPUTS_DEREFERENCEABLE"

        affected_data = []
        severity_data = []

        for _namespace, cve in bandit_config.namespaces.items():
            affected_data.append(
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
            )
            severity_data.append(
                {
                    "ID": cve.ad_hoc_cve_id,
                    # TODO severity
                    "severity": cve.severity,
                    # TODO description
                    "description": cve.description,
                    # TODO score
                    "score": 0,
                    # TODO CVSS_version
                    "CVSS_version": 3,
                    # TODO CVSS_vector
                    "CVSS_vector": "",
                    # TODO Ideally this comes from bisecting and pinpointing the
                    # bug's introduction to the codebase
                    "last_modified": "",
                }
            )

        with self.cve_db.with_cursor() as cursor:
            self.cve_db.populate_cve_metrics(severity_data, cursor)
            self.cve_db.populate_severity(severity_data, cursor, data_source)
            self.cve_db.populate_affected(affected_data, cursor, data_source)

        product_infos = {}
        for _namespace, cve in bandit_config.namespaces.items():
            product_infos_key = (
                cve.vendor,
                cve.product,
                cve.version,
            )
            product_infos.setdefault(
                product_infos_key,
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
            )
            product_info = product_infos[product_infos_key]
            for _namespace, cve in bandit_config.namespaces.items():
                yield ScanInfo(product_info, pathlib.Path(filename).resolve())

        # TODO VEX attached via linked data to ad-hoc CVE-ID
