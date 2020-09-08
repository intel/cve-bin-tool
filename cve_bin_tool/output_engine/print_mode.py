import os

from datetime import datetime
from jinja2 import Environment, FileSystemLoader

from ..util import CVEData


def html_print_mode(
    all_cve_data: CVEData,
    directory: str,
    products_with_cve: int,
    products_without_cve: int,
    total_files: int,
    full_html: bool = True,
) -> str:

    root = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(root, "print_mode")
    templates_env = Environment(loader=FileSystemLoader(templates_dir))

    temp_showcase = "templates/showcase.html"
    temp_content = "templates/content.html"
    temp_base = "templates/base.html"
    directory = directory

    showcase = templates_env.get_template(temp_showcase)
    content = templates_env.get_template(temp_content)
    rendered_report = []
    rendered_report.append(
        showcase.render(
            date=datetime.now().strftime("%d %b %Y"),
            directory=directory,
            products_with_cve=products_with_cve,
            products_without_cve=products_without_cve,
            total_files=total_files,
        )
    )

    rendered_report.append(content.render(all_cve_data=all_cve_data))

    rendered_report = "".join(rendered_report)

    if full_html:
        base = templates_env.get_template(temp_base)
        return base.render(content=rendered_report)
    else:
        return rendered_report
