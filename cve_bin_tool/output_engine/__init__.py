import csv
import json
import os
from logging import Logger
from typing import Dict, IO

from .console import output_console
from .html import output_html
from .util import generate_filename, format_output, add_extension_if_not
from ..cve_scanner import CVEData
from ..error_handler import ErrorHandler, ErrorMode
from ..log import LOGGER
from ..util import ProductInfo


def output_json(all_cve_data: Dict[ProductInfo, CVEData], outfile: IO):
    """ Output a JSON of CVEs """
    formatted_output = format_output(all_cve_data)
    json.dump(formatted_output, outfile, indent="    ")


def output_csv(all_cve_data: Dict[ProductInfo, CVEData], outfile):
    """ Output a CSV of CVEs """
    formatted_output = format_output(all_cve_data)
    writer = csv.DictWriter(
        outfile,
        fieldnames=[
            "vendor",
            "product",
            "version",
            "cve_number",
            "severity",
            "paths",
            "remarks",
            "comments",
        ],
    )
    writer.writeheader()
    writer.writerows(formatted_output)


class OutputEngine:
    def __init__(
        self,
        all_cve_data: Dict[ProductInfo, CVEData],
        scanned_dir: str,
        filename: str,
        themes_dir: str,
        logger: Logger = None,
        products_with_cve: int = 0,
        products_without_cve: int = 0,
        total_files: int = 0,
    ):
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.all_cve_data = all_cve_data
        self.scanned_dir = scanned_dir
        self.filename = os.path.abspath(filename) if filename else ""
        self.products_with_cve = products_with_cve
        self.products_without_cve = products_without_cve
        self.total_files = total_files
        self.themes_dir = themes_dir

    def output_cves(self, outfile, output_type="console"):
        """Output a list of CVEs
        format self.checkers[checker_name][version] = dict{id: severity}
        to other formats like CSV or JSON
        """
        if output_type == "json":
            output_json(self.all_cve_data, outfile)
        elif output_type == "csv":
            output_csv(self.all_cve_data, outfile)
        elif output_type == "html":
            output_html(
                self.all_cve_data,
                self.scanned_dir,
                self.filename,
                self.themes_dir,
                self.total_files,
                self.products_with_cve,
                self.products_without_cve,
                self.logger,
                outfile,
            )
        else:  # console, or anything else that is unrecognised
            output_console(self.all_cve_data)

    def output_file(self, output_type="console"):

        """ Generate a file for list of CVE """
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

            # check if the file already exists
            if os.path.isfile(self.filename):
                self.logger.warning(
                    f"Failed to write at '{self.filename}'. File already exists"
                )
                self.logger.info(
                    "Generating a new filename with Default Naming Convention"
                )
                self.filename = generate_filename(output_type)

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
        self.logger.info(f"Output stored at {self.filename}")

        # call to output_cves
        with open(self.filename, "w") as f:
            self.output_cves(f, output_type)
