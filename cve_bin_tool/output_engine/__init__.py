# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import csv
import json
import os
import time
from logging import Logger
from typing import IO, Dict, List, Union

from ..cve_scanner import CVEData
from ..cvedb import CVEDB
from ..error_handler import ErrorHandler, ErrorMode
from ..log import LOGGER
from ..util import ProductInfo
from ..version import VERSION
from . import pdfbuilder
from .console import output_console
from .html import output_html
from .util import (
    add_extension_if_not,
    format_output,
    generate_filename,
    intermediate_output,
)


def output_json(all_cve_data: Dict[ProductInfo, CVEData], outfile: IO):
    """Output a JSON of CVEs"""
    formatted_output = format_output(all_cve_data)
    json.dump(formatted_output, outfile, indent="    ")


def save_intermediate(
    all_cve_data: Dict[ProductInfo, CVEData],
    filename: str,
    tag: str,
    scanned_dir: str,
    products_with_cve: int,
    products_without_cve: int,
    total_files: int,
):
    """Save the intermediate report"""

    inter_output = intermediate_output(
        all_cve_data,
        tag,
        scanned_dir,
        products_with_cve,
        products_without_cve,
        total_files,
    )
    with open(filename, "w") as f:
        json.dump(inter_output, f, indent="    ")


def output_csv(all_cve_data: Dict[ProductInfo, CVEData], outfile):
    """Output a CSV of CVEs"""
    formatted_output = format_output(all_cve_data)
    writer = csv.DictWriter(
        outfile,
        fieldnames=[
            "vendor",
            "product",
            "version",
            "cve_number",
            "severity",
            "score",
            "cvss_version",
            "paths",
            "remarks",
            "comments",
        ],
    )
    writer.writeheader()
    writer.writerows(formatted_output)


def output_pdf(
    all_cve_data: Dict[ProductInfo, CVEData], is_report, products_with_cve, outfile
):
    """Output a PDF of CVEs"""
    cvedb_data = CVEDB()
    db_date = time.strftime(
        "%d %B %Y at %H:%M:%S", time.localtime(cvedb_data.get_db_update_date())
    )
    app_version = VERSION
    # Build document
    pdfdoc = pdfbuilder.PDFBuilder()
    cm = pdfdoc.cm
    severity_colour = {
        "UNKNOWN": pdfdoc.grey,
        "LOW": pdfdoc.blue,
        "MEDIUM": pdfdoc.green,
        "HIGH": pdfdoc.orange,
        "CRITICAL": pdfdoc.red,
    }
    pdfdoc.front_page("Vulnerability Report")
    pdfdoc.heading(1, "Introduction")
    pdfdoc.paragraph(
        "The identification of vulnerabilities has been performed using cve-bin-tool version "
        + app_version
    )
    pdfdoc.paragraph(
        "The data used has been obtained from the NVD database which was retrieved on "
        + db_date
        + " and contained "
        + str(cvedb_data.get_cve_count())
        + " entries."
    )

    if is_report:
        pdfdoc.heading(1, "List of All Scanned binaries")
        pdfdoc.createtable(
            "Productlist",
            ["Vendor", "Product", "Version"],
            pdfdoc.tblStyle,
        )
        row = 1
        for product_info, cve_data in all_cve_data.items():
            star_warn = True if "*" in product_info.vendor else False
            for cve in cve_data["cves"]:
                entry = [
                    product_info.vendor,
                    product_info.product,
                    product_info.version,
                ]
                pdfdoc.addrow(
                    "Productlist",
                    entry,
                )
                row += 1
        pdfdoc.showtable("Productlist", widths=[3 * cm, 2 * cm, 2 * cm])
        pdfdoc.paragraph("* vendors guessed by the tool") if star_warn else None
        pdfdoc.paragraph(
            f"There are {products_with_cve} products with vulnerabilities found."
        )
        pdfdoc.pagebreak()

    if products_with_cve != 0:
        pdfdoc.heading(1, "List of Identified Vulnerabilities")
        pdfdoc.paragraph(
            "The following vulnerabilities are reported against the identified versions of the libraries."
        )
        pdfdoc.createtable(
            "Productlist",
            ["Vendor", "Product", "Version", "CVE Number", "Severity"],
            pdfdoc.tblStyle,
            [10, 10, None, None, None],
        )
        row = 1
        star_warn = False
        for product_info, cve_data in all_cve_data.items():
            for cve in cve_data["cves"]:
                if cve.cve_number != "UNKNOWN":
                    if "*" in product_info.vendor:
                        star_warn = True
                    entry = [
                        product_info.vendor,
                        product_info.product,
                        product_info.version,
                        cve.cve_number,
                        cve.severity,
                    ]
                    pdfdoc.addrow(
                        "Productlist",
                        entry,
                        [
                            (
                                "TEXTCOLOR",
                                (3, row),
                                (4, row),
                                severity_colour[cve.severity],
                            ),
                            ("FONT", (3, row), (4, row), "Helvetica-Bold"),
                        ],
                    )
                    row += 1

        pdfdoc.showtable("Productlist", widths=[3 * cm, 3 * cm, 2 * cm, 4 * cm, 3 * cm])
    pdfdoc.paragraph("* vendors guessed by the tool") if star_warn else None

    pdfdoc.pagebreak()
    pdfdoc.paragraph("END OF DOCUMENT.")
    pdfdoc.publish(outfile)


class OutputEngine:
    def __init__(
        self,
        all_cve_data: Dict[ProductInfo, CVEData],
        scanned_dir: str,
        filename: str,
        themes_dir: str,
        time_of_last_update,
        tag: str,
        logger: Logger = None,
        products_with_cve: int = 0,
        products_without_cve: int = 0,
        total_files: int = 0,
        is_report: bool = False,
        append: Union[str, bool] = False,
        merge_report: Union[None, List[str]] = None,
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.all_cve_data = all_cve_data
        self.scanned_dir = scanned_dir
        self.filename = os.path.abspath(filename) if filename else ""
        self.products_with_cve = products_with_cve
        self.products_without_cve = products_without_cve
        self.total_files = total_files
        self.themes_dir = themes_dir
        self.is_report = is_report
        self.time_of_last_update = time_of_last_update
        self.append = append
        self.tag = tag
        self.merge_report = merge_report

    def output_cves(self, outfile, output_type="console"):
        """Output a list of CVEs
        format self.checkers[checker_name][version] = dict{id: severity}
        to other formats like CSV or JSON
        """
        if output_type == "json":
            output_json(self.all_cve_data, outfile)
        elif output_type == "csv":
            output_csv(self.all_cve_data, outfile)
        elif output_type == "pdf":
            output_pdf(
                self.all_cve_data, self.is_report, self.products_with_cve, outfile
            )
        elif output_type == "html":
            output_html(
                self.all_cve_data,
                self.scanned_dir,
                self.filename,
                self.themes_dir,
                self.total_files,
                self.products_with_cve,
                self.products_without_cve,
                self.merge_report,
                self.logger,
                outfile,
            )
        else:  # console, or anything else that is unrecognised
            output_console(self.all_cve_data, self.time_of_last_update)

        if isinstance(self.append, str):
            save_intermediate(
                self.all_cve_data,
                self.append,
                self.tag,
                self.scanned_dir,
                self.products_with_cve,
                self.products_without_cve,
                self.total_files,
            )
            self.logger.info(f"Output stored at {self.append}")

    def output_file(self, output_type="console"):

        """Generate a file for list of CVE"""
        if self.append:
            if isinstance(self.append, str):
                self.append = self.check_dir_path(
                    self.append, output_type="json", prefix="intermediate"
                )
                self.append = add_extension_if_not(self.append, "json")
                self.append = self.check_file_path(
                    self.append, output_type="json", prefix="intermediate"
                )
            else:
                # file path for intermediate report not given
                self.append = generate_filename("json", "intermediate")

        if output_type == "console":
            # short circuit file opening logic if we are actually
            # just writing to stdout
            self.output_cves(self.filename, output_type)
            return

        # Check if we need to generate a filename
        if not self.filename:
            self.filename = generate_filename(output_type)
        else:
            # check and add if the filename doesn't contain extension
            self.filename = add_extension_if_not(self.filename, output_type)

            self.filename = self.check_file_path(self.filename, output_type)

            # try opening that file
            with ErrorHandler(mode=ErrorMode.Ignore) as e:
                with open(self.filename, "w") as f:
                    f.write("testing")
                os.remove(self.filename)
            if e.exit_code:
                self.logger.info(
                    f"Exception {e.exc_val} occurred while writing to the file {self.filename} "
                    "Switching Back to Default Naming Convention"
                )
                self.filename = generate_filename(output_type)

        # Log the filename generated
        if output_type == "html" or output_type == "pdf":
            self.logger.info(f"{output_type.upper()} report stored at {self.filename}")
        else:
            self.logger.info(f"Output stored at {self.filename}")

        # call to output_cves
        mode = "w"
        if output_type == "pdf":
            mode = "wb"
        with open(self.filename, mode) as f:
            self.output_cves(f, output_type)

    def check_file_path(self, filepath: str, output_type: str, prefix: str = "output"):
        # check if the file already exists
        if os.path.isfile(filepath):
            self.logger.warning(f"Failed to write at '{filepath}'. File already exists")
            self.logger.info("Generating a new filename with Default Naming Convention")
            filepath = generate_filename(output_type, prefix)

        return filepath

    def check_dir_path(
        self, filepath: str, output_type: str, prefix: str = "intermediate"
    ):

        if os.path.isdir(filepath):
            self.logger.info(
                f"Generating a new filename with Default Naming Convention in directory path {filepath}"
            )
            filename = os.path.basename(generate_filename(output_type, prefix))
            filepath = os.path.join(filepath, filename)

        return filepath
