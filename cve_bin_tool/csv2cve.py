#!/usr/bin/python3
from __future__ import print_function

import argparse
import csv
import sys

from .cli import Scanner
from .NVDAutoUpdate import NVDSQLite

ERR_BADCSV = -1
ERR_MISSINGCOLUMN = -2


def main(argv=sys.argv, outfile=sys.stdout):
    """ Take a list of package information + versions from a CSV file,
    and output a list of matching CVES """

    parser = argparse.ArgumentParser(
        prog="csv2cve",
        description="This tool takes a list of software + versions from a CSV file and outputs a list of CVEs known to affect those versions",
    )
    parser.add_argument(
        "csv_file",
        action="store",
        help="CSV file with package data. Must contain vendor,package,version, where vendor and package match entries in the National Vulnerability Database.",
    )

    if len(argv) <= 1:
        parser.print_help()
        return 0

    args = parser.parse_args(argv[1:])

    csv2cve(args.csv_file)


def csv2cve(filename):
    # Parse the csv file
    print("opening file: {}".format(filename))
    cveoutput = []

    with open(filename) as csvfile:
        csvdata = csv.DictReader(csvfile, delimiter=",")  # "," is default anyhow

        if csvdata is None or csvdata.fieldnames is None:
            print("Error: invalid CSV", file=sys.stderr)
            return ERR_BADCSV

        required_columns = ["vendor", "package", "version"]
        for column in required_columns:
            if column not in csvdata.fieldnames:
                print("Error: no {} column found".format(column), file=sys.stderr)
                return ERR_MISSINGCOLUMN

        # Initialize the NVD database
        nvd = NVDSQLite()
        nvd.get_cvelist_if_stale()
        nvd.open()

        # Initialize the scanner
        scanner = Scanner(nvd)

        # Go row by row and look for CVEs
        for row in csvdata:
            print(
                "CVES for {} {}, version {}".format(
                    row["vendor"], row["package"], row["version"]
                )
            )
            vpkg_pair = [[row["vendor"], row["package"]]]
            cves = scanner.get_cves(vpkg_pair, row["version"])
            if cves:
                print("\n".join(sorted(cves.keys())))
                cveoutput.append(cves.keys())
            else:
                print("No CVEs found. Is the vendor/package info correct?")
            print("")

        # close down the NVD database
        nvd.close()
        return cveoutput


if __name__ == "__main__":
    sys.exit(main())
