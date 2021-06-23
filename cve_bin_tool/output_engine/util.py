# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
output_engine/util.py - Provides helper functions for OutputEngine.
"""

import os
from collections import defaultdict
from datetime import datetime
from typing import DefaultDict, Dict, List, Union

from ..util import CVE, CVEData, ProductInfo, Remarks


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


def format_output(all_cve_data: Dict[ProductInfo, CVEData]) -> List[Dict[str, str]]:
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
            formatted_output.append(
                {
                    "vendor": product_info.vendor,
                    "product": product_info.product,
                    "version": product_info.version,
                    "cve_number": cve.cve_number,
                    "severity": cve.severity,
                    "score": str(cve.score),
                    "cvss_version": str(cve.cvss_version),
                    "paths": ", ".join(cve_data["paths"]),
                    "remarks": cve.remarks.name,
                    "comments": cve.comments,
                }
            )

    return formatted_output


def intermediate_output(
    all_cve_data: Dict[ProductInfo, CVEData],
    tag: str,
    scanned_dir: str,
    products_with_cve: int,
    products_without_cve: int,
    total_files: int,
) -> Dict[Dict[str, Union[str, int]], List[Dict[str, str]]]:
    """
    summary: Generate an intermediate output in the list of dictionary format with some metadata.
    Returns:
        formatted_output: Dict[Dict[str, Union[str, int]], List[Dict[str, str]]]
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
    adds one.

    Args:
        filename (str): filename from OutputEngine
        output_type (str): contains a value from ["json", "csv", "html"]

    Returns:
        str: Filename with extension according to output_type
    """
    if not filename.endswith(f".{output_type}"):
        updated_filename = f"{filename}.{output_type}"
        return updated_filename
    else:
        return filename


def group_cve_by_remark(
    cve_by_product: List[CVE],
) -> DefaultDict[Remarks, List[Dict[str, str]]]:
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
    cve_by_remarks: DefaultDict[Remarks, List[Dict[str, str]]] = defaultdict(list)
    for cve in cve_by_product:
        cve_by_remarks[cve.remarks].append(
            {
                "cve_number": cve.cve_number,
                "severity": cve.severity,
                "description": cve.description,
            }
        )
    return cve_by_remarks
