#!/usr/bin/python3
# pylint: disable=invalid-name, useless-object-inheritance
# useless-object-inheritance kept for python2 compatibility

"""
This tool scans for a number of common, vulnerable open source components
(openssl, libpng, libxml2, expat and a few others) to let you know if your
system includes common libraries with known vulnerabilities.  It emits a list
of CVE numbers that may be relevant to your binary based on the versions.  It
cannot detect backported fixes.
"""

import argparse
import logging
import os
import platform
import sys
import textwrap
from collections import ChainMap
from typing import Dict

import pkg_resources
from .output_engine import OutputEngine

from .config import ConfigParser
from .util import ProductInfo
from .cve_scanner import CVEScanner
from .cvedb import CVEDB, OLD_CACHE_DIR
from .error_handler import (
    excepthook,
    ErrorHandler,
    InsufficientArgs,
    EmptyCache,
    ErrorMode,
)
from .input_engine import (
    InputEngine,
    TriageData,
)
from .log import LOGGER
from .version import VERSION
from .version_scanner import VersionScanner

sys.excepthook = excepthook  # Always install excepthook for entrypoint module.


class StringToListAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        values = list(map(lambda val: val.strip(), values.split(",")))
        setattr(namespace, self.dest, values)


def main(argv=None):
    """ Scan a binary file for certain open source libraries that may have CVEs """
    argv = argv or sys.argv

    # Reset logger level to info
    LOGGER.setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        prog="cve-bin-tool",
        description=textwrap.dedent(
            """
            The CVE Binary Tool scans for a number of common, vulnerable open source
            components (openssl, libpng, libxml2, expat and a few others) to let you know
            if a given directory or binary file includes common libraries with known
            vulnerabilities.
            """
        ),
        epilog=textwrap.fill(
            f'Available checkers: {", ".join(VersionScanner.available_checkers())}'
        )
        + "\n\nPlease disclose issues responsibly!",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "directory", help="directory to scan", nargs="?", default=None
    )
    input_group.add_argument(
        "-e",
        "--exclude",
        action=StringToListAction,
        help="Comma separated Exclude directory path",
        default=None,
    )

    input_group.add_argument(
        "-i", "--input-file", action="store", default="", help="provide input filename",
    )
    input_group.add_argument(
        "-C", "--config", action="store", default="", help="provide config file"
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-q", "--quiet", action="store_true", help="suppress output"
    )
    output_group.add_argument(
        "-l",
        "--log",
        help="log level (default: info)",
        dest="log_level",
        action="store",
        choices=["debug", "info", "warning", "error", "critical"],
    )
    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        help="provide output filename (default: output to stdout)",
    )
    output_group.add_argument(
        "--html-theme",
        action="store",
        help="provide custom theme directory for HTML Report",
    )
    output_group.add_argument(
        "-f",
        "--format",
        action="store",
        choices=["csv", "json", "console", "html"],
        help="update output format (default: console)",
    )
    output_group.add_argument(
        "-c",
        "--cvss",
        action="store",
        help="minimum CVSS score (as integer in range 0 to 10) to report (default: 0)",
    )
    output_group.add_argument(
        "-S",
        "--severity",
        action="store",
        choices=["low", "medium", "high", "critical"],
        help="minimum CVE severity to report (default: low)",
    )
    parser.add_argument("-V", "--version", action="version", version=VERSION)
    parser.add_argument(
        "-u",
        "--update",
        action="store",
        choices=["now", "daily", "never", "latest"],
        help="update schedule for NVD database (default: daily)",
    )
    parser.add_argument(
        "-x", "--extract", action="store_true", help="autoextract compressed files",
    )
    parser.add_argument(
        "--disable-version-check",
        action="store_true",
        help="skips checking for a new version",
    )

    checker_group = parser.add_argument_group("Checkers")
    checker_group.add_argument(
        "-s",
        "--skips",
        dest="skips",
        action=StringToListAction,
        type=str,
        help="comma-separated list of checkers to disable",
    )
    checker_group.add_argument(
        "-r",
        "--runs",
        dest="runs",
        action=StringToListAction,
        type=str,
        help="comma-separated list of checkers to enable",
    )
    defaults = {
        "directory": "",
        "exclude": [],
        "input_file": "",
        "log_level": "info",
        "format": "console",
        "cvss": 0,
        "severity": "low",
        "update": "daily",
        "extract": False,
        "disable_version_check": False,
        "skips": "",
        "runs": "",
        "quiet": False,
        "output_file": "",
        "html_theme": "",
    }

    with ErrorHandler(mode=ErrorMode.NoTrace):
        raw_args = parser.parse_args(argv[1:])
        args = {key: value for key, value in vars(raw_args).items() if value}

    configs = {}
    if args.get("config"):
        conf = ConfigParser(args["config"])
        configs = conf.parse_config()

    args = ChainMap(args, configs, defaults)

    # logging and error related settings
    if args["log_level"]:
        LOGGER.setLevel(args["log_level"].upper())

    if args["quiet"]:
        LOGGER.setLevel(logging.CRITICAL)

    if 0 < LOGGER.level <= 10:
        error_mode = ErrorMode.FullTrace
    elif LOGGER.level >= 50:
        error_mode = ErrorMode.NoTrace
    else:
        error_mode = ErrorMode.TruncTrace

    if platform.system() != "Linux":
        warning_nolinux = """
                          **********************************************
                          Warning: this utility was developed for Linux.
                          You may need to install additional utilities
                          to use it on other operating systems.
                          **********************************************
                          """
        LOGGER.warning(warning_nolinux)

    # Database update related settings
    # Connect to the database
    cvedb_orig = CVEDB(
        version_check=not args["disable_version_check"], error_mode=error_mode
    )

    # if OLD_CACHE_DIR (from cvedb.py) exists, print warning
    if os.path.exists(OLD_CACHE_DIR):
        LOGGER.warning(
            f"Obsolete cache dir {OLD_CACHE_DIR} is no longer needed and can be removed."
        )

    # Clear data if -u now is set
    if args["update"] == "now":
        cvedb_orig.clear_cached_data()

    if args["update"] == "latest":
        cvedb_orig.refresh_cache_and_update_db()

    # update db if needed
    if args["update"] != "never":
        cvedb_orig.get_cvelist_if_stale()
    else:
        LOGGER.warning("Not verifying CVE DB cache")
        if not cvedb_orig.nvd_years():
            with ErrorHandler(mode=error_mode, logger=LOGGER):
                raise EmptyCache(cvedb_orig.cachedir)

    # Input validation
    if not args["directory"] and not args["input_file"]:
        parser.print_usage()
        with ErrorHandler(logger=LOGGER, mode=ErrorMode.NoTrace):
            raise InsufficientArgs(
                "Please specify a directory to scan or an input file required"
            )

    if args["directory"] and not os.path.exists(args["directory"]):
        parser.print_usage()
        with ErrorHandler(logger=LOGGER, mode=ErrorMode.NoTrace):
            raise FileNotFoundError("Directory/File doesn't exist")

    # Checkers related settings
    skips = args["skips"]
    if args["runs"]:
        runs = args["runs"]
        skips = list(
            map(
                lambda checker: checker.name,
                filter(
                    lambda checker: checker.name not in runs,
                    pkg_resources.iter_entry_points("cve_bin_tool.checker"),
                ),
            )
        )

    # CSVScanner related settings
    score = 0
    if args["severity"]:
        # Set minimum CVSS score based on severity
        cvss_score = {"low": 0, "medium": 4, "high": 7, "critical": 9}
        score = cvss_score[args["severity"]]
    if int(args["cvss"]) > 0:
        score = int(args["cvss"])

    with CVEScanner(score=score) as cve_scanner:
        triage_data: TriageData
        total_files: int = 0
        parsed_data: Dict[ProductInfo, TriageData] = {}

        if args["input_file"]:
            input_engine = InputEngine(
                args["input_file"], logger=LOGGER, error_mode=error_mode
            )
            parsed_data = input_engine.parse_input()
            if not args["directory"]:
                for product_info, triage_data in parsed_data.items():
                    LOGGER.warning(f"{product_info}, {triage_data}")
                    cve_scanner.get_cves(product_info, triage_data)
        if args["directory"]:
            version_scanner = VersionScanner(
                should_extract=args["extract"],
                exclude_folders=args["exclude"],
                error_mode=error_mode,
            )
            version_scanner.remove_skiplist(skips)
            LOGGER.info(version_scanner.print_checkers())
            for scan_info in version_scanner.recursive_scan(args["directory"]):
                if scan_info:
                    product_info, path = scan_info
                    LOGGER.debug(f"{product_info}: {path}")
                    triage_data = parsed_data.get(product_info, {"default": {}})
                    # Ignore paths from triage_data if we are scanning directory
                    triage_data["paths"] = {path}
                    cve_scanner.get_cves(product_info, triage_data)
            total_files = version_scanner.total_scanned_files

        LOGGER.info("")
        LOGGER.info("Overall CVE summary: ")
        LOGGER.info(
            f"There are {cve_scanner.products_with_cve} products with known CVEs detected"
        )
        if cve_scanner.products_with_cve > 0:
            affected_string = ", ".join(
                map(
                    lambda product_version: "".join(str(product_version)),
                    cve_scanner.affected(),
                )
            )
            LOGGER.info(f"Known CVEs in {affected_string}:")

            # Creates a Object for OutputEngine
            output = OutputEngine(
                all_cve_data=cve_scanner.all_cve_data,
                scanned_dir=args["directory"],
                filename=args["output_file"],
                themes_dir=args["html_theme"],
                products_with_cve=cve_scanner.products_with_cve,
                products_without_cve=cve_scanner.products_without_cve,
                total_files=total_files,
            )

            if not args["quiet"]:
                output.output_file(args["format"])

        # Use the number of products with known cves as error code
        # as requested by folk planning to automate use of this script.
        # If no cves found, then the program exits cleanly.
        return cve_scanner.products_with_cve


if __name__ == "__main__":
    if os.getenv("NO_EXIT_CVE_NUM"):
        main()
    else:
        sys.exit(main())
