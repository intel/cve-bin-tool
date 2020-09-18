import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List

import plotly.graph_objects as go
from jinja2 import Environment, FileSystemLoader
from jinja2.environment import Template

from .util import group_cve_by_remark
from .print_mode import html_print_mode
from ..log import LOGGER
from ..util import ProductInfo, CVEData, Remarks
from ..version import VERSION


def render_cves(
    hid: str, cve_row: Template, tag: str, cves: List[Dict[str, str]]
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
                tag=tag,
                var_id=f"{hid}{i}{tag}",
                fix_id=hid,
            )
        )
    return "".join(list_cves)


def output_html(
    all_cve_data: Dict[ProductInfo, CVEData],
    scanned_dir: str,
    filename: str,
    theme_dir: str,
    total_files: int,
    products_with_cve: int,
    products_without_cve: int,
    logger: LOGGER,
    outfile,
):
    """Returns a HTML report for CVE's"""

    # Step 1: Load all the templates

    # Root folder where html_reports is present
    root = os.path.dirname(os.path.abspath(__file__))

    # Template Directory contains all the html files
    templates_dir = os.path.join(root, "html_reports")
    templates_env = Environment(loader=FileSystemLoader([theme_dir, templates_dir]))

    temp_base = "templates/base.html"
    temp_dash = "templates/dashboard.html"
    temp_product = "templates/row_product.html"
    temp_cve = "templates/row_cve.html"

    base = templates_env.get_template(temp_base)
    dashboard = templates_env.get_template(temp_dash)
    cve_row = templates_env.get_template(temp_cve)
    product_row = templates_env.get_template(temp_product)

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
        autosize=True, legend_orientation="h",
    )
    product_pie.update_traces(
        hoverinfo="label+percent",
        textinfo="value",
        textfont_size=14,
        marker=dict(colors=["#d80032", "#1a936f"], line=dict(color="white", width=2),),
    )

    # dash graph2: Product CVE's Graph
    cve_bar = go.Figure()
    for product_info, cve_data in all_cve_data.items():
        # Check if product contains CVEs
        if cve_data["cves"]:
            cve_bar.add_trace(
                go.Bar(
                    x=[
                        f"{product_info.vendor}-{product_info.product}({product_info.version})"
                    ],
                    y=[len(cve_data["cves"])],
                    name=f"{product_info.product}-{product_info.version}",
                )
            )

    # Chart configuration for cve_bar
    cve_bar.update_layout(yaxis_title="Number of CVE's",)

    all_paths = defaultdict(list)

    products_found = []
    # List of Products
    for product_info, cve_data in all_cve_data.items():
        # Check if product contains CVEs
        if cve_data["cves"]:

            # group product wise cves on the basis of remarks
            cve_by_remark = group_cve_by_remark(cve_data["cves"])

            # hid is unique for each product
            hid = f"{product_info.vendor}{product_info.product}{''.join(product_info.version.split('.'))}"

            new_cves = render_cves(
                hid, cve_row, "NEW", cve_by_remark[Remarks.NewFound],
            )
            mitigated_cves = render_cves(
                hid, cve_row, "MITIGATED", cve_by_remark[Remarks.Mitigated],
            )
            confirmed_cves = render_cves(
                hid, cve_row, "CONFIRMED", cve_by_remark[Remarks.Confirmed],
            )
            unexplored_cves = render_cves(
                hid, cve_row, "UNEXPLORED", cve_by_remark[Remarks.Unexplored],
            )
            ignored_cves = render_cves(
                hid, cve_row, "IGNORED", cve_by_remark[Remarks.Ignored],
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
            colors = [colors_avail[label] for label in analysis_data.keys()]
            analysis_pie.update_traces(
                hoverinfo="label+percent",
                textinfo="value",
                textfont_size=14,
                marker=dict(colors=colors, line=dict(color="white", width=2),),
            )
            analysis_pie.update_layout(
                autosize=True,
                height=300,
                legend_orientation="h",
                margin=dict(l=0, r=20, t=0, b=0),
                # paper_bgcolor="LightSteelBlue",
            )

            products_found.append(
                product_row.render(
                    vendor=product_info.vendor,
                    name=product_info.product,
                    version=product_info.version,
                    cve_count=len(cve_data["cves"]),
                    severity_analysis=analysis_pie.to_html(
                        full_html=False, include_plotlyjs=False
                    ),
                    fix_id=hid,
                    paths=cve_data["paths"],
                    len_paths=len(cve_data["paths"]),
                    new_cves=new_cves,
                    mitigated_cves=mitigated_cves,
                    confirmed_cves=confirmed_cves,
                    unexplored_cves=unexplored_cves,
                    ignored_cves=ignored_cves,
                )
            )

            # update all_paths
            for path in cve_data["paths"]:
                all_paths[path].append(hid)

    # Dashboard Rendering
    dashboard = dashboard.render(
        graph_cves=cve_bar.to_html(full_html=False, include_plotlyjs=False),
        graph_products=product_pie.to_html(full_html=False, include_plotlyjs=False),
        total_files=total_files,
        products_with_cve=products_with_cve,
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
    js_jquery = "js/jquery.js"

    script_main = templates_env.get_template(js_main)
    script_bootstrap = templates_env.get_template(js_bootstrap)
    script_plotly = templates_env.get_template(js_plotly)
    script_jquery = templates_env.get_template(js_jquery)

    # Render the base html to generate report
    outfile.write(
        base.render(
            date=datetime.now().strftime("%d %b %Y"),
            dashboard=dashboard,
            scanned_dir=scanned_dir,
            all_paths=all_paths,
            print_mode=html_print_mode(
                all_cve_data,
                scanned_dir,
                products_with_cve,
                products_without_cve,
                total_files,
                full_html=False,
            ),
            products_found="".join(products_found),
            version=VERSION,
            style_main=style_main.render(),
            style_bootstrap=style_bootstrap.render(),
            script_main=script_main.render(),
            script_jquery=script_jquery.render(),
            script_bootstrap=script_bootstrap.render(),
            script_plotly=script_plotly.render(),
        )
    )

    logger.info(f"HTML Report is stored at location {filename}")
