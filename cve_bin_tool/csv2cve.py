#!/usr/bin/python3
from __future__ import print_function

import argparse
import csv
import sys

from collections import defaultdict
from .cvedb import CVEDB
from .cli import LogAction
from .log import LOGGER
from .OutputEngine import OutputEngine


class CSV2CVE(object):
    """Generate CVE Output from a CSV file """

    ERR_BADCSV = -1
    ERR_MISSINGCOLUMN = -2
    ERR_BADFILENAME = -3

    def __init__(self, filename=None, logger=None):
        if logger is None:
            self.logger = LOGGER.getChild(self.__class__.__name__)
        self.filename = filename
        self.cvedb = CVEDB()

    def db_update(self, update):

        # Clear data if -u now is set
        if update == "now":
            self.cvedb.clear_cached_data()

        # update data to the latest available data
        if update == "latest":
            self.cvedb.refresh_cache_and_update_db()

        # skip the database update
        if update != "never":
            self.cvedb.get_cvelist_if_stale()

    def update_logLevel(self, log_level):
        if log_level:
            self.logger.setLevel(log_level)

    def generate_modules(self):
        """Summary: Returns Dictionary containing Product_Name, Version,
        CVE_Number and Severity associated with each module

        Returns:
        Example --> {'libjpeg-turbo': {'2.0.1': 
                            {'CVE-2018-19664': 'MEDIUM', 
                            'CVE-2018-20330': 'HIGH'}}
        """

        self.logger.debug(f"Opening File: {self.filename}")

        # we will try opening the file. If unsuccessful, Raise FileNotFound.
        try:
            with open(self.filename) as csvfile:
                csvdata = csv.DictReader(
                    csvfile, delimiter=","
                )  # "," is default anyhow

                if csvdata is None or csvdata.fieldnames is None:
                    self.logger.error("Error: invalid CSV")
                    return self.ERR_BADCSV

                required_columns = {"vendor", "product", "version"}
                csv_columns = set(csvdata.fieldnames)
                missing_columns = required_columns - csv_columns
                if missing_columns != set():
                    self.logger.error(f"Error: no {missing_columns} columns found")
                    return self.ERR_MISSINGCOLUMN

                all_cves = defaultdict(dict)

                # Go row by row and look for CVEs
                for row in csvdata:
                    cves = self.cvedb.get_cves(
                        row["vendor"], row["product"], row["version"]
                    )

                    if cves:
                        self.logger.debug(
                            f'Found CVES for {row["vendor"]} {row["product"]}, version {row["version"]}'
                        )
                        # if we found CVES add to the all_cves
                        all_cves[row["product"]][row["version"]] = cves

                    else:
                        self.logger.debug(
                            f'No CVEs found for {row["vendor"]} {row["product"]}, version {row["version"]}. Is the vendor/product info correct?'
                        )
                        # Vendor Product is wrong mark CVE_Number and Severity = UNKNOWN
                        all_cves[row["product"]][row["version"]] = {
                            "UNKNOWN": "UNKNOWN"
                        }

                # close down the NVD database
                self.cvedb.close()

                return all_cves

        except Exception as E:
            self.logger.error(E)
            return self.ERR_BADFILENAME

    def generate_output(self, outfile):
        """generates the output from output engine"""

        modules = self.generate_modules()
        try:
            if (modules < 0) or modules is None:
                return modules
        except Exception as e:
            self.output_engine = OutputEngine(modules=modules, logger=self.logger)
            self.output_engine.output_cves(outfile)


def main(argv=None, outfile=None):
    """ Take a list of product information + versions from a CSV file,
    and output a list of matching CVES """

    if argv is None:
        argv = sys.argv

    if outfile is None:
        outfile = sys.stdout

    parser = argparse.ArgumentParser(
        prog="csv2cve",
        description="This tool takes a list of software + versions from a CSV file \
        and outputs a list of CVEs known to affect those versions",
    )
    parser.add_argument(
        "csv_file",
        action="store",
        help="CSV file with product data. Must contain vendor,product,version, \
        where vendor and product match entries in the National Vulnerability Database.",
    )
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-l",
        "--log",
        help="log level (default: info)",
        dest="log_level",
        action=LogAction,
        choices=["debug", "info", "warning", "error", "critical"],
    )
    parser.add_argument(
        "-u",
        "--update",
        action="store",
        choices=["now", "daily", "never", "latest"],
        default="daily",
        help="update schedule for NVD database (default: daily)",
    )

    if len(argv) <= 1:
        parser.print_help()
        return 0

    args = parser.parse_args(argv[1:])

    # Create a CSV2CVE object
    csv2cve = CSV2CVE(filename=args.csv_file)
    csv2cve.db_update(update=args.update)
    csv2cve.update_logLevel(log_level=args.log_level)
    csv2cve.generate_output(outfile)


if __name__ == "__main__":
    sys.exit(main())
