# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from logging import Logger
from pathlib import Path

import plotly.graph_objects as go
from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja2.environment import Template

from cve_bin_tool.merge import MergeReports

from ..util import CVEData, ProductInfo, Remarks, VersionInfo
from ..version import VERSION
from .print_mode import html_print_mode
from .util import group_cve_by_remark

SEVERITY_TYPES_COLOR = {
    "CRITICAL": "red",
    "HIGH": "blue",
    "MEDIUM": "yellow",
    "LOW": "green",
    "UNKNOWN": "black",
}


def render_cves(
    hid: str, cve_row: Template, tag: str, cves: list[dict[str, str]]
) -> str:
    """Return rendered form of CVEs using cve_row template

    Args:
        hid (str): Unique id for each product
        cve_row (Template): JinjaTemplate to be used for rendering
        tag (str): Marked by user. (default: New) Can be anything [NEW, MITIGATED, IGNORED, UNEXPLORED]
        cves (List[Dict[str, str]]): List of CVEs present in the products.

    Returns:
        str: CVE(s) in rendered form
    """
    list_cves = []
    for i, cve in enumerate(cves):
        # render CVE template with data and add to list_cves
        list_cves.append(
            cve_row.render(
                cve_number=cve["cve_number"],
                severity=cve["severity"],
                description=cve["description"],
                comment=cve["comments"],
                tag=tag,
                var_id=f"{hid}{i}{tag}",
                fix_id=hid,
            )
        )
    return "".join(list_cves)


def output_html(
    all_cve_data: dict[ProductInfo, CVEData],
    all_cve_version_info: dict[str, VersionInfo] | None,
    scanned_dir: str,
    filename: str,
    theme_dir: str,
    total_files: int,
    products_with_cve: int,
    products_without_cve: int,
    merge_report: None | MergeReports,
    logger: Logger,
    outfile,
    affected_versions: int = 0,
):
    """Returns a HTML report for CVE's"""

    # Step 1: Load all the templates

    # Root folder where html_reports is present
    root = Path(__file__).parent.resolve()

    # Template Directory contains all the html files
    templates_dir = str(root / "html_reports")
    templates_env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape(
            enabled_extensions=("html"), disabled_extensions=("css,js")
        ),
    )

    temp_base = "templates/base.html"
    temp_dash = "templates/dashboard.html"
    temp_product = "templates/row_product.html"
    temp_cve = "templates/row_cve.html"
    temp_intermediate = "templates/intermediate.html"

    base = templates_env.get_template(temp_base)
    dashboard = templates_env.get_template(temp_dash)
    cve_row = templates_env.get_template(temp_cve)
    product_row = templates_env.get_template(temp_product)
    # Load merge template if the report is generated from intermediate reports
    if merge_report:
        merged = templates_env.get_template(temp_intermediate)
        (
            products_trace,
            total_files_trace,
            intermediate_timeline,
            severity_trace,
        ) = load_timeline_from_merged(merge_report)

        # Intermediate Graphs Rendering
        intermediate = merged.render(
            products_trace=products_trace.to_html(
                full_html=False, include_plotlyjs=False
            ),
            total_files_trace=total_files_trace.to_html(
                full_html=False, include_plotlyjs=False
            ),
            intermediate_timeline=intermediate_timeline.to_html(
                full_html=False, include_plotlyjs=False
            ),
            severity_trace=severity_trace.to_html(
                full_html=False, include_plotlyjs=False
            ),
        )
    else:
        intermediate = None

    # Step 2: Prepare Charts
    # Start generating graph with the data

    # dash graph1: Products Vulnerability Graph
    product_pie = go.Figure(
        data=[
            go.Pie(
                labels=["Vulnerable", "No Known Vulnerability"],
                values=[products_with_cve, products_without_cve],
                hole=0.4,
            )
        ]
    )

    # Chart configuration for product_pie
    product_pie.update_layout(
        autosize=True,
        legend_orientation="h",
    )
    product_pie.update_traces(
        hoverinfo="label+percent",
        textinfo="value",
        textfont_size=14,
        marker=dict(
            colors=["#d80032", "#1a936f"],
            line=dict(color="white", width=2),
        ),
    )

    # dash graph2: Product CVE's Graph
    cve_bar = go.Figure()
    data_by_cve_remarks: dict = {
        "NEW": {"x": [], "y": []},
        "MITIGATED": {"x": [], "y": []},
        "CONFIRMED": {"x": [], "y": []},
        "UNEXPLORED": {"x": [], "y": []},
        "FALSE POSITIVE": {"x": [], "y": []},
        "NOT AFFECTED": {"x": [], "y": []},
    }
    for product_info, cve_data in all_cve_data.items():
        # Check if product contains CVEs
        if cve_data["cves"]:
            cve_by_remark = group_cve_by_remark(cve_data["cves"])
            for key, val in [
                ["NEW", len(cve_by_remark[Remarks.NewFound])],
                ["MITIGATED", len(cve_by_remark[Remarks.Mitigated])],
                ["CONFIRMED", len(cve_by_remark[Remarks.Confirmed])],
                ["UNEXPLORED", len(cve_by_remark[Remarks.Unexplored])],
                ["FALSE POSITIVE", len(cve_by_remark[Remarks.FalsePositive])],
                ["NOT AFFECTED", len(cve_by_remark[Remarks.NotAffected])],
            ]:
                x = (
                    f"{product_info.vendor}-{product_info.product}({product_info.version})"
                    if product_info.vendor != "UNKNOWN"
                    else f"{product_info.product}({product_info.version})"
                )
                y = 0 if cve_data["cves"][0][1] == "UNKNOWN" else val
                data_by_cve_remarks[key]["x"].append(x)
                data_by_cve_remarks[key]["y"].append(y)

    for key, val in data_by_cve_remarks.items():
        cve_bar.add_trace(
            go.Bar(
                x=val["x"],
                y=val["y"],
                name=key,
            )
        )

    # Chart configuration for cve_bar
    cve_bar.update_layout(yaxis_title="Number of CVE's", barmode="stack")

    all_paths = defaultdict(list)

    star_warn = ""
    products_found = []
    cve_remarks = {
        "NEW": 0,
        "MITIGATED": 0,
        "CONFIRMED": 0,
        "UNEXPLORED": 0,
        "FALSE POSITIVE": 0,
        "NOT AFFECTED": 0,
    }

    cve_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

    cve_by_metrics: defaultdict[Remarks, list[dict[str, str]]] = defaultdict(list)
    for product_info, cve_data in all_cve_data.items():
        if cve_data["cves"]:
            for cve in cve_data["cves"]:
                probability = "-"
                percentile = "-"

                for metric, field in cve.metric.items():
                    if metric == "EPSS":
                        probability = round(field[0] * 100, 4)
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

    cve_metric_html_rows = []
    for remarks in sorted(cve_by_metrics):
        for cve in cve_by_metrics[remarks]:
            row_color = "table-success"
            if cve["severity"] == "CRITICAL":
                row_color = "table-danger"
            elif cve["severity"] == "HIGH":
                row_color = "table-primary"
            elif cve["severity"] == "MEDIUM":
                row_color = "table-warning"

            html_row = f"""
                <tr class="{row_color}">
                    <th scope="row">{cve["cve_number"]}</th>
                    <td>{cve["cvss_version"]}</td>
                    <td>{cve["cvss_score"]}</td>
                    <td>{cve["epss_probability"]}</td>
                    <td>{cve["epss_percentile"]}</td>
                </tr>
            """
            cve_metric_html_rows.append(html_row)
    # Join the HTML rows to create the full table content
    table_content = "\n".join(cve_metric_html_rows)

    # List of Products
    for product_info, cve_data in all_cve_data.items():
        # Check if product contains CVEs
        if cve_data["cves"]:
            # group product wise cves on the basis of remarks
            cve_by_remark = group_cve_by_remark(cve_data["cves"])

            cve_remarks["NEW"] += len(cve_by_remark[Remarks.NewFound])
            cve_remarks["MITIGATED"] += len(cve_by_remark[Remarks.Mitigated])
            cve_remarks["CONFIRMED"] += len(cve_by_remark[Remarks.Confirmed])
            cve_remarks["UNEXPLORED"] += len(cve_by_remark[Remarks.Unexplored])
            cve_remarks["FALSE POSITIVE"] += len(cve_by_remark[Remarks.FalsePositive])
            cve_remarks["NOT AFFECTED"] += len(cve_by_remark[Remarks.NotAffected])

            for cve in cve_data["cves"]:
                cve_severity[cve.severity] += 1

            # hid is unique for each product
            if product_info.vendor != "UNKNOWN":
                hid = f"{product_info.vendor}{product_info.product}{''.join(product_info.version.split('.'))}"
            else:
                hid = (
                    f"{product_info.product}{''.join(product_info.version.split('.'))}"
                )
            new_cves = render_cves(
                hid,
                cve_row,
                "NEW",
                cve_by_remark[Remarks.NewFound],
            )
            mitigated_cves = render_cves(
                hid,
                cve_row,
                "MITIGATED",
                cve_by_remark[Remarks.Mitigated],
            )
            confirmed_cves = render_cves(
                hid,
                cve_row,
                "CONFIRMED",
                cve_by_remark[Remarks.Confirmed],
            )
            unexplored_cves = render_cves(
                hid,
                cve_row,
                "UNEXPLORED",
                cve_by_remark[Remarks.Unexplored],
            )
            false_positive_cves = render_cves(
                hid,
                cve_row,
                "FALSE POSITIVE",
                cve_by_remark[Remarks.FalsePositive],
            )
            not_affected_cves = render_cves(
                hid,
                cve_row,
                "NOT AFFECTED",
                cve_by_remark[Remarks.NotAffected],
            )

            analysis_data = Counter(cve.severity for cve in cve_data["cves"])

            # initialize a figure object for Analysis Chart
            analysis_pie = go.Figure(
                data=[
                    go.Pie(
                        labels=list(analysis_data.keys()),
                        values=list(analysis_data.values()),
                        hole=0.4,
                    )
                ]
            )
            colors_avail = {
                "CRITICAL": "#f25f5c",
                "HIGH": "#ee6c4d",
                "MEDIUM": "#f4d35e",
                "LOW": "#90a955",
                "UNKNOWN": "#808080",
            }
            colors = [
                colors_avail[label.split("-")[0]] for label in analysis_data.keys()
            ]
            analysis_pie.update_traces(
                hoverinfo="label+percent",
                textinfo="value",
                textfont_size=14,
                marker=dict(
                    colors=colors,
                    line=dict(color="white", width=2),
                ),
            )
            analysis_pie.update_layout(
                autosize=True,
                height=300,
                legend_orientation="h",
                margin=dict(l=0, r=20, t=0, b=0),
                # paper_bgcolor="LightSteelBlue",
            )

            remarks = ""

            if new_cves:
                remarks += "new "
            if mitigated_cves:
                remarks += "mitigated "
            if confirmed_cves:
                remarks += "confirmed "
            if unexplored_cves:
                remarks += "unexplored "
            if false_positive_cves:
                remarks += "false_positive "
            if not_affected_cves:
                remarks += "not_affected "

            products_found.append(
                product_row.render(
                    vendor=product_info.vendor,
                    name=product_info.product,
                    version=product_info.version,
                    cve_count=(
                        0
                        if cve_data["cves"][0][1] == "UNKNOWN"
                        else len(cve_data["cves"])
                    ),
                    severity_analysis=analysis_pie.to_html(
                        full_html=False, include_plotlyjs=False
                    ),
                    remarks=remarks,
                    fix_id=hid,
                    paths=cve_data["paths"],
                    len_paths=len(cve_data["paths"]),
                    new_cves=new_cves,
                    mitigated_cves=mitigated_cves,
                    confirmed_cves=confirmed_cves,
                    unexplored_cves=unexplored_cves,
                    false_positive_cves=false_positive_cves,
                    not_affected_cves=not_affected_cves,
                )
            )

            if "*" in product_info.vendor:
                star_warn = "* vendors guessed by the tool"

            # update all_paths
            for path in cve_data["paths"]:
                all_paths[path].append(hid)

    # Dashboard Rendering
    dashboard = dashboard.render(
        graph_cves=cve_bar.to_html(full_html=False, include_plotlyjs=False),
        graph_products=product_pie.to_html(full_html=False, include_plotlyjs=False),
        directory=scanned_dir,
        total_files=total_files,
        products_with_cve=products_with_cve,
        products_without_cve=products_without_cve,
        cve_remarks=cve_remarks,
        cve_severity=cve_severity,
        table_content=table_content,
    )

    # try to load the bigger files just before the generation of report

    # css template names
    css_main = "css/main.css"
    css_bootstrap = "css/bootstrap.css"

    style_main = templates_env.get_template(css_main)
    style_bootstrap = templates_env.get_template(css_bootstrap)

    # js template names
    js_main = "js/main.js"
    js_bootstrap = "js/bootstrap.js"
    js_plotly = "js/plotly.js"

    script_main = templates_env.get_template(js_main)
    script_bootstrap = templates_env.get_template(js_bootstrap)
    script_plotly = templates_env.get_template(js_plotly)

    # Render the base html to generate report
    outfile.write(
        base.render(
            date=datetime.now().strftime("%d %b %Y"),
            dashboard=dashboard,
            intermediate=intermediate,
            scanned_dir=scanned_dir,
            all_paths=all_paths,
            print_mode=html_print_mode(
                all_cve_data,
                all_cve_version_info,
                scanned_dir,
                products_with_cve,
                products_without_cve,
                total_files,
                star_warn,
                merge_report,
                version=VERSION,
                full_html=False,
                affected_versions=affected_versions,
            ),
            products_found="".join(products_found),
            version=VERSION,
            star_warn=star_warn,
            style_main=style_main.render(),
            style_bootstrap=style_bootstrap.render(),
            script_main=script_main.render(),
            script_bootstrap=script_bootstrap.render(),
            script_plotly=script_plotly.render(),
        )
    )


def get_intermediate_label(metadata: dict[str, str]) -> str:
    """Return the x-axis timestamp label for intermediate reports"""

    if metadata["tag"]:
        timestamp_label = f'{datetime.strptime(metadata["timestamp"], "%Y-%m-%d.%H-%M-%S").strftime("%d %b %H:%M")}-{metadata["tag"]}'
    else:
        timestamp_label = f'{datetime.strptime(metadata["timestamp"], "%Y-%m-%d.%H-%M-%S").strftime("%d %b %H:%M")}'

    return timestamp_label


def load_timeline_from_merged(merge_report: MergeReports):
    """Load metadata from intermediate reports and return graphs to construct the HTML file"""

    timestamps = []
    products_with_cve = []
    products_without_cve = []
    total_files = []
    severity_count_list = []

    for inter_file in reversed(merge_report.intermediate_cve_data):
        products_with_cve.append(inter_file["metadata"]["products_with_cve"])
        products_without_cve.append(inter_file["metadata"]["products_without_cve"])
        total_files.append(inter_file["metadata"]["total_files"])
        severity_count_list.append(inter_file["metadata"]["severity"])
        timestamps.append(get_intermediate_label(inter_file["metadata"]))

    intermediate_cve_scanner_list = merge_report.get_intermediate_cve_scanner(
        merge_report.intermediate_cve_data, merge_report.score
    )

    cve_bar_data = []
    cve_product_list = set()

    # Create a intermediate data wise product dictionary
    for cve_scanner in intermediate_cve_scanner_list:
        data = dict()
        for product_info, cve_data in cve_scanner.all_cve_data.items():
            # Check if product contains CVEs
            if cve_data["cves"]:
                x = f"{product_info.product}({product_info.version})"
                y = 0 if cve_data["cves"][0][1] == "UNKNOWN" else len(cve_data["cves"])
                data[x] = y
                cve_product_list.add(x)

        cve_bar_data.append(data)

    intermediate_timeline = go.Figure()
    cve_product_list = list(cve_product_list)
    # Add product wise stacked bar
    for key in cve_product_list:
        intermediate_timeline.add_trace(
            go.Bar(
                name=key,
                x=timestamps,
                y=[data[key] if key in data else 0 for data in cve_bar_data],
            )
        )

    # Chart configuration for intermediate_timeline
    intermediate_timeline.update_layout(
        autosize=True,
        legend_orientation="v",
        barmode="stack",
        yaxis_title="Products with CVE",
        height=400,
    )

    # Graph for severity count
    severity_trace = go.Figure()
    for severity_type in list(SEVERITY_TYPES_COLOR.keys()):
        severity_trace.add_trace(
            go.Scatter(
                name=severity_type,
                x=timestamps,
                y=[count[severity_type] for count in severity_count_list],
                line=dict(color=SEVERITY_TYPES_COLOR[severity_type]),
            )
        )

    # Chart configuration for severity traces
    severity_trace.update_layout(
        autosize=True,
        legend_orientation="v",
        yaxis_title="Severity",
        height=300,
    )

    # Graph for product with/without cves count
    products_trace = go.Figure()
    products_trace.add_trace(
        go.Scatter(
            name="Products with CVE",
            x=timestamps,
            y=products_with_cve,
            xperiodalignment="middle",
        )
    )
    products_trace.add_trace(
        go.Scatter(
            name="Products without CVE",
            x=timestamps,
            y=products_without_cve,
            xperiodalignment="middle",
        ),
    )
    products_trace.update_layout(
        autosize=True,
        legend_orientation="v",
        yaxis_title="Products",
        height=300,
    )

    # Graph for total_files in each intermediate file
    total_files_trace = go.Figure()
    total_files_trace.add_trace(
        go.Scatter(
            name="Total Files",
            x=timestamps,
            y=total_files,
            xperiodalignment="middle",
        )
    )
    total_files_trace.update_layout(
        autosize=True,
        legend_orientation="v",
        yaxis_title="Total Files",
        height=300,
    )

    return products_trace, total_files_trace, intermediate_timeline, severity_trace
