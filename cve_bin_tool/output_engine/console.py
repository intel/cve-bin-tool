# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import textwrap
from collections import defaultdict
from datetime import datetime
from typing import DefaultDict, Dict, List

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..cve_scanner import CVEData
from ..input_engine import Remarks
from ..linkify import linkify_cve
from ..theme import cve_theme
from ..util import ProductInfo


def output_console(
    all_cve_data: Dict[ProductInfo, CVEData],
    time_of_last_update,
    console=Console(theme=cve_theme),
):
    """Output list of CVEs in a tabular format with color support"""

    console._width = 120
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    time_of_last_update = time_of_last_update.strftime("%Y-%m-%d  %H:%M:%S")

    console.print(
        Markdown(
            textwrap.dedent(
                f"""
                # CVE BINARY TOOL
                - cve-bin-tool Report Generated: {now}
                - Time of last update of CVE Data: {time_of_last_update}
                """
            )
        )
    )

    remarks_colors = {
        Remarks.Mitigated: "green",
        Remarks.Confirmed: "red",
        Remarks.NewFound: "blue",
        Remarks.Unexplored: "yellow",
        Remarks.Ignored: "white",
    }

    cve_by_remarks: DefaultDict[Remarks, List[Dict[str, str]]] = defaultdict(list)
    # group cve_data by its remarks
    for product_info, cve_data in all_cve_data.items():
        for cve in cve_data["cves"]:
            cve_by_remarks[cve.remarks].append(
                {
                    "vendor": product_info.vendor,
                    "product": product_info.product,
                    "version": product_info.version,
                    "cve_number": cve.cve_number,
                    "severity": cve.severity,
                    "score": cve.score,
                    "cvss_version": cve.cvss_version,
                }
            )

    for remarks in sorted(cve_by_remarks):
        color = remarks_colors[remarks]
        console.print(Panel(f"[{color}] {remarks.name} CVEs [/{color}]", expand=False))
        # table instance
        table = Table()

        # Add Head Columns to the Table
        table.add_column("Vendor")
        table.add_column("Product")
        table.add_column("Version")
        table.add_column("CVE Number")
        table.add_column("Severity")
        table.add_column("Score (CVSS Version)")
        # table.add_column("CVSS Version")

        for cve_data in cve_by_remarks[remarks]:
            color = cve_data["severity"].lower()
            table.add_row(
                Text.styled(cve_data["vendor"], color),
                Text.styled(cve_data["product"], color),
                Text.styled(cve_data["version"], color),
                linkify_cve(Text.styled(cve_data["cve_number"], color)),
                Text.styled(cve_data["severity"], color),
                Text.styled(
                    str(cve_data["score"])
                    + " (v"
                    + str(cve_data["cvss_version"])
                    + ")",
                    color,
                ),
            )
        # Print the table to the console
        console.print(table)
        for cve_data in cve_by_remarks[remarks]:
            if "*" in cve_data["vendor"]:
                console.print("* vendors guessed by the tool")
                break
