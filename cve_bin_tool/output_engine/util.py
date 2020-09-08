"""
output_engine/util.py - Provides helper functions for OutputEngine.
"""

import os
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, DefaultDict

from ..util import ProductInfo, Remarks, CVEData, CVE


def generate_filename(extension: str) -> str:
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
        os.path.join(os.getcwd(), f"output.cve-bin-tool.{now}.{extension}")
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
                            "severity": "LOW"
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
                    "paths": ", ".join(cve_data["paths"]),
                    "remarks": cve.remarks.name,
                    "comments": cve.comments,
                }
            )

    return formatted_output


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
