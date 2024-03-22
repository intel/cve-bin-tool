# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import textwrap
from collections import defaultdict
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..cve_scanner import CVEData
from ..input_engine import Remarks
from ..linkify import linkify_cve
from ..theme import cve_theme
from ..util import ProductInfo, VersionInfo
from ..version import VERSION
from .util import (
    format_path,
    format_version_range,
    get_cve_summary,
    get_latest_upstream_stable_version,
)


def output_console(*args: Any):
    """wrapper function for _output_console to enable output to a file"""

    ls_args = list(args)
    output_file = ls_args[-1]
    ls_args.pop()

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            console = Console(theme=cve_theme, file=f)
            ls_args.append(console)
            _output_console_nowrap(*ls_args)
    else:
        _output_console_nowrap(*ls_args)


def _output_console_nowrap(
    all_cve_data: dict[ProductInfo, CVEData],
    all_cve_version_info: dict[str, VersionInfo],
    time_of_last_update: datetime,
    affected_versions: int,
    exploits: bool = False,
    metrics: bool = False,
    all_product_data=None,
    offline: bool = False,
    width: int = None,
    console: Console = Console(theme=cve_theme),
):
    """Output list of CVEs in a tabular format with color support"""

    console._width = width
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    time_of_last_update = time_of_last_update.strftime("%Y-%m-%d  %H:%M:%S")

    console.print(
        Markdown(
            textwrap.dedent(
                f"""
                # CVE BINARY TOOL version: {VERSION}
                - Report Generated: {now}
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
        Remarks.FalsePositive: "white",
        Remarks.NotAffected: "white",
    }

    # Create table instance for CVE Summary
    table = Table()
    # Add Head Columns to the Table
    table.add_column("Severity")
    table.add_column("Count")
    summary = get_cve_summary(all_cve_data, exploits)
    summary_color = {
        "CRITICAL": "red",
        "HIGH": "blue",
        "MEDIUM": "yellow",
        "LOW": "green",
        "UNKNOWN": "white",
    }

    for severity, count in summary.items():
        color = summary_color[severity.split("-")[0]]
        cells = [
            Text.styled(severity, color),
            Text.styled(str(count), color),
        ]
        table.add_row(*cells)
    # Print the table to the console
    console.print(Panel("CVE SUMMARY", expand=False))
    console.print(table)

    # Create table instance for CPE Summary
    table = Table()
    # Add Head Columns to the Table
    table.add_column("Vendor")
    table.add_column("Product")
    table.add_column("Version")
    table.add_column("Latest Upstream Stable Version")
    table.add_column("CRITICAL CVEs Count")
    table.add_column("HIGH CVEs Count")
    table.add_column("MEDIUM CVEs Count")
    table.add_column("LOW CVEs Count")
    table.add_column("UNKNOWN CVEs Count")
    table.add_column("TOTAL CVEs Count")
    if all_product_data is not None:
        for product_data in sorted(all_product_data, key=lambda item: item.product):
            color = None
            summary = get_cve_summary(
                {product_data: all_cve_data[product_data]}, exploits
            )

            # Display package with the color of the highest CVE
            for severity, count in summary.items():
                if color is None and count > 0:
                    color = summary_color[severity.split("-")[0]]

            if all_product_data[product_data] != 0:
                if offline:
                    latest_stable_version = "UNKNOWN (offline mode)"
                else:
                    latest_stable_version = get_latest_upstream_stable_version(
                        product_data
                    )
                cells = [
                    Text.styled(product_data.vendor, color),
                    Text.styled(product_data.product, color),
                    Text.styled(product_data.version, color),
                    Text.styled(latest_stable_version, color),
                ]
                for severity, count in summary.items():
                    if count > 0:
                        color = summary_color[severity.split("-")[0]]
                    else:
                        color = "white"
                    cells += [
                        Text.styled(str(count), color),
                    ]
                cells += [
                    Text.styled(str(all_product_data[product_data]), color),
                ]
                table.add_row(*cells)
    # Print the table to the console
    console.print(Panel("CPE SUMMARY", expand=False))
    console.print(table)

    cve_by_remarks: defaultdict[Remarks, list[dict[str, str]]] = defaultdict(list)
    cve_by_paths: defaultdict[Remarks, list[dict[str, str]]] = defaultdict(list)
    # group cve_data by its remarks and separately by paths
    for product_info, cve_data in all_cve_data.items():
        for cve in cve_data["cves"]:
            probability = "-"
            percentile = "-"
            for metric, field in cve.metric.items():
                if metric == "EPSS":
                    probability = str(round(field[0], 5))
                    percentile = str(field[1])
            cve_by_remarks[cve.remarks].append(
                {
                    "vendor": product_info.vendor,
                    "product": product_info.product,
                    "version": product_info.version,
                    "cve_number": cve.cve_number,
                    "source": cve.data_source,
                    "severity": cve.severity,
                    "score": cve.score,
                    "cvss_version": cve.cvss_version,
                    "epss_probability": probability,
                    "epss_percentile": percentile,
                }
            )
            path_elements = ", ".join(filter(None, cve_data["paths"]))
            for path_element in path_elements.split(","):
                path_entry = {
                    "vendor": product_info.vendor,
                    "product": product_info.product,
                    "version": product_info.version,
                    "paths": path_element,
                }
                if path_entry not in cve_by_paths[cve.remarks]:
                    cve_by_paths[cve.remarks].append(path_entry)
            if affected_versions != 0:
                try:
                    version_info = all_cve_version_info[cve.cve_number]
                except KeyError:  # TODO: handle 'UNKNOWN' and some cves more cleanly
                    version_info = VersionInfo("", "", "", "")
                cve_by_remarks[cve.remarks][-1].update(
                    {"affected_versions": format_version_range(version_info)}
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
        table.add_column("Source")
        table.add_column("Severity")
        table.add_column("Score (CVSS Version)")
        if metrics:
            table.add_column("EPSS probability")
            table.add_column("EPSS percentile")
        if affected_versions != 0:
            table.add_column("Affected Versions")

        for cve_data in cve_by_remarks[remarks]:
            color = cve_data["severity"].split("-")[0].lower()
            if cve_data["score"] == "unknown":
                cvss_text = "unknown"
            else:
                cvss_text = (
                    str(cve_data["score"]) + " (v" + str(cve_data["cvss_version"]) + ")"
                )
            cells = [
                Text.styled(cve_data["vendor"], color),
                Text.styled(cve_data["product"], color),
                Text.styled(cve_data["version"], color),
                linkify_cve(Text.styled(cve_data["cve_number"], color)),
                Text.styled(cve_data["source"], color),
                Text.styled(cve_data["severity"], color),
                Text.styled(cvss_text, color),
            ]
            if metrics:
                cells.append(Text.styled(cve_data["epss_probability"], color))
                cells.append(Text.styled(cve_data["epss_percentile"], color))
            if affected_versions != 0:
                cells.append(Text.styled(cve_data["affected_versions"], color))
            table.add_row(*cells)
        # Print the table to the console
        console.print(table)
        for cve_data in cve_by_remarks[remarks]:
            if "*" in cve_data["vendor"]:
                console.print("* vendors guessed by the tool")
                break

        # Show table of vulnerable products mapped to filename paths
        # As names can be long, these maybe replaced with a note which
        # is printed at end of table

        def validate_cell_length(cell_name, cell_type):
            # If long name replace with a note
            if len(cell_name) > 30:
                if [cell_name, cell_type] not in note_data:
                    note_data.append([cell_name, cell_type])
                return (
                    cell_type
                    + str(note_data.index([cell_name, cell_type]))
                    + " (see below)"
                )
            return cell_name

        i = 0
        note_data = []
        # Table instance
        table = Table()

        # Add Head Columns to the Table
        table.add_column("Vendor")
        table.add_column("Product")
        table.add_column("Version")
        table.add_column("Root")
        table.add_column("Filename")
        color = "green"
        for cve_data in cve_by_paths[remarks]:
            path_root = format_path(cve_data["paths"])
            cells = [
                Text.styled(validate_cell_length(cve_data["vendor"], "Vendor "), color),
                Text.styled(
                    validate_cell_length(cve_data["product"], "Product "), color
                ),
                Text.styled(cve_data["version"], color),
                Text.styled(validate_cell_length(path_root[0], "Root "), color),
                Text.styled(validate_cell_length(path_root[1], "Path "), color),
            ]
            table.add_row(*cells)
        # Print the table to the console
        console.print(table)
        # Show truncated filenames if necessary
        if len(note_data) > 0:
            console.print("\n")
            i = 0
            for note in note_data:
                # Note is a tuple [pathname, pathtype]
                console.print(f"{note[1]}{i} : {note[0]}")
                i = i + 1

    # List of scanned products with no identified vulnerabilities
    if all_product_data is not None:
        color = "green"
        console.print(
            Panel(
                f"[{color}] Products with No Identified Vulnerabilities [/{color}]",
                expand=False,
            )
        )
        table = Table()

        # Add Head Columns to the Table
        table.add_column("Vendor")
        table.add_column("Product")
        table.add_column("Version")

        products_with_cves = []
        for product_info, cve_data in all_cve_data.items():
            if len(cve_data["cves"]):
                products_with_cves.append(product_info.product)

        for product_data in all_product_data:
            if (
                all_product_data[product_data] == 0
                and product_data.product not in products_with_cves
            ):
                cells = [
                    Text.styled(product_data.vendor, color),
                    Text.styled(product_data.product, color),
                    Text.styled(product_data.version, color),
                ]
                table.add_row(*cells)
        # Print the table to the console
        console.print(table)

    if metrics:
        table = Table()
        # Add Head Columns to the Table
        table.add_column("CVE")
        table.add_column("CVSS_version")
        table.add_column("CVSS_score")
        table.add_column("EPSS_probability")
        table.add_column("EPSS_percentile")
        color = "green"

        cve_by_metrics: defaultdict[Remarks, list[dict[str, str]]] = defaultdict(list)
        # group cve_data by its remarks and separately by paths
        for product_info, cve_data in all_cve_data.items():
            for cve in cve_data["cves"]:
                probability = "-"
                percentile = "-"
                for metric, field in cve.metric.items():
                    if metric == "EPSS":
                        probability = round(field[0], 5)
                        percentile = field[1]
                cve_by_metrics[cve.remarks].append(
                    {
                        "cve_number": cve.cve_number,
                        "cvss_version": str(cve.cvss_version),
                        "cvss_score": str(cve.score),
                        "epss_probability": str(probability),
                        "epss_percentile": str(percentile),
                        "severity": cve.severity,
                    }
                )

        for remarks in sorted(cve_by_remarks):
            color = remarks_colors[remarks]
            for cve in cve_by_metrics[remarks]:
                color = cve["severity"].split("-")[0].lower()
                cells = [
                    Text.styled(cve["cve_number"], color),
                    Text.styled(cve["cvss_version"], color),
                    Text.styled(str(cve["cvss_score"]), color),
                    Text.styled(cve["epss_probability"], color),
                    Text.styled(cve["epss_percentile"], color),
                ]
                table.add_row(*cells)
        # Print the table to the console
        console.print(table)
