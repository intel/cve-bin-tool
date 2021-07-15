# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from datetime import datetime
from typing import Union

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cve_bin_tool.merge import MergeReports

from ..util import CVEData


def html_print_mode(
    all_cve_data: CVEData,
    directory: str,
    products_with_cve: int,
    products_without_cve: int,
    total_files: int,
    star_warn: str,
    merge_report: Union[None, MergeReports],
    version: str,
    full_html: bool = True,
) -> str:

    root = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(root, "print_mode")
    templates_env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape(
            enabled_extensions=("html"), disabled_extensions=("css,js")
        ),
    )

    temp_showcase = "templates/showcase.html"
    temp_content = "templates/content.html"
    temp_base = "templates/base.html"
    temp_intermediate = "templates/intermediate_content.html"

    showcase = templates_env.get_template(temp_showcase)
    content = templates_env.get_template(temp_content)
    intermediate_content = None
    rendered_report = []
    rendered_report.append(
        showcase.render(
            date=datetime.now().strftime("%d %b %Y"),
            directory=directory,
            products_with_cve=products_with_cve,
            products_without_cve=products_without_cve,
            total_files=total_files,
            version=version,
        )
    )
    if merge_report:
        intermediate_content = templates_env.get_template(temp_intermediate)
        rendered_report.append(
            intermediate_content.render(
                intermediate_data=merge_report.intermediate_cve_data,
            )
        )
    rendered_report.append(
        content.render(
            all_cve_data=all_cve_data, directory=directory, star_warn=star_warn
        )
    )

    rendered_report = "".join(rendered_report)

    if full_html:
        base = templates_env.get_template(temp_base)
        return base.render(content=rendered_report)
    else:
        return rendered_report
