# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
output_engine/util.py - Provides helper functions for OutputEngine.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime

from ..util import CVE, CVEData, ProductInfo, Remarks, VersionInfo


def get_cve_summary(
    all_cve_data: dict[ProductInfo, CVEData], exploits: bool = False
) -> dict[str, int]:
    """
    summary: Generate a summary count for the number of CVEs in each severity category

    Args:
        Dictionary of CVEs

    Returns:
        Dictionary containing count of CVEs in each severity category
    """
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    if exploits:
        summary.update(
            {
                "CRITICAL-EXPLOIT": 0,
                "HIGH-EXPLOIT": 0,
                "MEDIUM-EXPLOIT": 0,
                "LOW-EXPLOIT": 0,
            }
        )
    for cve_data in all_cve_data.values():
        for s in summary.keys():
            summary[s] += sum(
                isinstance(cve, CVE)
                and cve.severity == s
                and cve.remarks not in [Remarks.Ignored, Remarks.Mitigated]
                for cve in cve_data["cves"]
            )

    return summary


def generate_filename(extension: str, prefix: str = "output") -> str:
    """
    summary: Generate a unique filename with extension provided.
    Function use inbuilt datetime function to generate unique filename.

    Args:
        extension str : Can be any value from list[CSV, JSON, HTML]

    Returns:
        str: unique generated filename
    """
    now = datetime.now().strftime("%Y-%m-%d.%H-%M-%S")

    filename = os.path.abspath(
        os.path.join(os.getcwd(), f"{prefix}.cve-bin-tool.{now}.{extension}")
    )

    return filename


def format_version_range(version_info: VersionInfo) -> str:
    """
    Format version info to desirable output

    Example:
    ```
        format_version_range('', '', '', '') => "-"
        format_version_range('2.2.8', '', '2.2.11', '') => "[2.2.8 - 2.2.11]"
        format_version_range('2.2.8', '', '', '2.2.11') => "[2.2.8 - 2.2.11)"
        format_version_range('', '2.2.8', '2.2.11', '') => "(2.2.8 - 2.2.11]"
        format_version_range('', '2.2.8', '', '2.2.11') => "(2.2.8 - 2.2.11])"
        format_version_range('2.2.8', '', '', '') => ">= 2.2.8"
        format_version_range('', '2.2.8', '', '') => "> 2.2.8"
        format_version_range('', '', '2.2.11', '') => "<= 2.2.11"
        format_version_range('', '', '', '2.2.11') => "< 2.2.11"
    ```

    Reference for Interval terminologies: https://en.wikipedia.org/wiki/Interval_(mathematics)
    """

    (start_including, start_excluding, end_including, end_excluding) = version_info
    if start_including and end_including:
        return f"[{start_including} - {end_including}]"
    if start_including and end_excluding:
        return f"[{start_including} - {end_excluding})"
    if start_excluding and end_including:
        return f"({start_excluding} - {end_including}]"
    if start_excluding and end_excluding:
        return f"({start_excluding} - {end_excluding})"
    if start_including:
        return f">= {start_including}"
    if start_excluding:
        return f"> {start_excluding}"
    if end_including:
        return f"<= {end_including}"
    if end_excluding:
        return f"< {end_excluding}"
    return "-"


def format_output(
    all_cve_data: dict[ProductInfo, CVEData],
    all_cve_version_info: dict[str, VersionInfo] | None = None,
    detailed: bool = False,
    affected_versions: int = 0,
) -> list[dict[str, str]]:
    """
    summary: format output in the list of dictionary format.

    Returns:
        formatted_output: List[Dict[str, str]]
        - example:  [
                        {
                            "vendor": "haxx"
                            "product": "curl",
                            "version": "1.2.1",
                            "cve_number": "CVE-1234-1234",
                            "severity": "LOW",
                            "score": "1.2",
                            "cvss_version": "2",
                            "paths": "",
                            "remarks": "NewFound",
                            "comments": "",
                        },
                        ...
                    ]
    """
    formatted_output = []
    for product_info, cve_data in all_cve_data.items():
        for cve in cve_data["cves"]:
            if isinstance(cve, str):
                continue
            details = {
                "vendor": product_info.vendor,
                "product": product_info.product,
                "version": product_info.version,
                "cve_number": cve.cve_number,
                "severity": cve.severity,
                "score": str(cve.score),
                "source": cve.data_source,
                "cvss_version": str(cve.cvss_version),
                "cvss_vector": cve.cvss_vector,
                "paths": ", ".join(cve_data["paths"]),
                "remarks": cve.remarks.name,
                "comments": cve.comments,
            }
            if detailed:
                details["description"] = cve.description
            if affected_versions != 0:
                if (
                    all_cve_version_info is not None
                    and cve.cve_number in all_cve_version_info
                ):
                    version_info = all_cve_version_info[cve.cve_number]
                else:  # TODO: handle 'UNKNOWN' and some cves more cleanly
                    version_info = VersionInfo("", "", "", "")
                details["affected_versions"] = format_version_range(version_info)
            formatted_output.append(details)

    return formatted_output


def intermediate_output(
    all_cve_data: dict[ProductInfo, CVEData],
    tag: str,
    scanned_dir: str,
    products_with_cve: int,
    products_without_cve: int,
    total_files: int,
) -> dict[dict[str, str | int], list[dict[str, str]]]:
    """
    summary: Generate an intermediate output in the list of dictionary format with some metadata.
    Returns:
        formatted_output: Dict[Dict[str, str | int], List[Dict[str, str]]]
        - example:  {
                        metadata:   {
                                        timestamp: 2021-03-24T11:07:55Z,
                                        "tag": "backend",
                                        "scanned_dir": "/home/project/binaries",
                                        "products_with_cve": 139,
                                        "products_without_cve": 2,
                                        "total_files": 49
                                    }
                        report:     [
                                        {
                                            "vendor": "haxx"
                                            "product": "curl",
                                            "version": "1.2.1",
                                            "cve_number": "CVE-1234-1234",
                                            "severity": "LOW"
                                        },
                                        ...
                                    ]
                    }
    """

    return {
        "metadata": {
            "timestamp": datetime.now().strftime("%Y-%m-%d.%H-%M-%S"),
            "tag": tag,
            "scanned_dir": scanned_dir,
            "products_with_cve": products_with_cve,
            "products_without_cve": products_without_cve,
            "total_files": total_files,
        },
        "report": format_output(all_cve_data),
    }


def add_extension_if_not(filename: str, output_type: str) -> str:
    """
    summary: Checks if the filename ends with the extension and if not
    adds one. And if the filename ends with a different extension it replaces the extension.

    Args:
        filename (str): filename from OutputEngine
        output_type (str): contains a value from ["json", "csv", "html", "pdf"]

    Returns:
        str: Filename with extension according to output_type
    """
    import re

    extensions = ["json", "csv", "html", "pdf", "txt"]
    for extension in extensions:
        if not filename.endswith(f".{extension}"):
            continue
        if extension == output_type:
            return filename
        filename = re.sub(f".{extension}$", f".{output_type}", filename)
        return filename
    filename = f"{filename}.{output_type}"
    return filename


def group_cve_by_remark(
    cve_by_product: list[CVE] | set[str],
) -> defaultdict[Remarks, list[dict[str, str]]]:
    """Return a dict containing CVE details dict mapped to Remark as Key.

    Example:
    cve_by_remark = {
            "NEW":[
                {
                    "cve_number": "CVE-XXX-XXX",
                    "severity": "High",
                    "decription: "Lorem Ipsm",
                },
                {...}
            ],
            "IGNORED": [{...},{..}],
        }


    Args:
        cve_by_product (List[CVE]): List of CVE(s) that needs to be grouped

    Returns:
        DefaultDict[Remarks, List[Dict[str, str]]]: CVEs grouped by remark stored in default dict
    """
    cve_by_remarks: defaultdict[Remarks, list[dict[str, str]]] = defaultdict(list)
    for cve in cve_by_product:
        cve_by_remarks[cve.remarks].append(
            {
                "cve_number": cve.cve_number,
                "severity": cve.severity,
                "description": cve.description,
                "vector": cve.cvss_vector,
            }
        )
    return cve_by_remarks


def format_path(path_element: str) -> list[str]:
    """Extract filenames from path element"""
    path = path_element.strip().split(" contains ")
    if len(path) > 1:
        # path_element is an archive. Final element will be the filename
        return [os.path.basename(path[0]), os.path.basename(path[-1])]
    return [os.path.dirname(path[0]), os.path.basename(path[0])]
