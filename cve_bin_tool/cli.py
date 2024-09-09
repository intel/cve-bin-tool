# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


# This file is not meant to be run directly.
# It should be properly installed so the checkers will load correctly.
# Refer to:
#       manual (https://cve-bin-tool.readthedocs.io/en/latest/MANUAL.html)
#       on how to use the tool, or
#       installation guide (https://cve-bin-tool.readthedocs.io/en/latest/README.html#installing-cve-binary-tool)
#       on how to install the tool.

"""
This tool scans for a number of common, vulnerable open source components
(openssl, libpng, libxml2, libexpat and a few others) to let you know if your
system includes common libraries with known vulnerabilities.  It emits a list
of CVE numbers that may be relevant to your binary based on the versions.
There is a flag to enable information about backported fixes for specific
Linux distributions, but cve-bin-tool cannot detect backported fixes outside
of those published lists.
"""

from __future__ import annotations

import argparse
import importlib.util
import logging
import os
import platform
import shutil
import sys
import textwrap
import time
from collections import ChainMap
from pathlib import Path

from cve_bin_tool.available_fix import (
    AvailableFixReport,
    get_available_fix_supported_distros,
    get_backport_supported_distros,
)
from cve_bin_tool.config import ConfigParser
from cve_bin_tool.config_generator import config_generator
from cve_bin_tool.cve_scanner import CVEScanner
from cve_bin_tool.cvedb import CVEDB, OLD_CACHE_DIR
from cve_bin_tool.data_sources import (
    DataSourceSupport,
    curl_source,
    epss_source,
    gad_source,
    nvd_source,
    osv_source,
    purl2cpe_source,
    redhat_source,
)
from cve_bin_tool.error_handler import (
    ERROR_CODES,
    CVEDataMissing,
    CVEDBNotExist,
    CVEDBOutdatedSchema,
    EmptyCache,
    ErrorHandler,
    ErrorMode,
    InsufficientArgs,
    InvalidExtensionError,
    MirrorError,
    PDFOutputUnavailable,
    VEXError,
    excepthook,
)
from cve_bin_tool.input_engine import InputEngine, TriageData
from cve_bin_tool.log import LOGGER
from cve_bin_tool.merge import MergeReports
from cve_bin_tool.output_engine import OutputEngine
from cve_bin_tool.package_list_parser import PackageListParser
from cve_bin_tool.sbom_manager.parse import SBOMParse
from cve_bin_tool.sbom_manager.sbom_detection import sbom_detection
from cve_bin_tool.util import ProductInfo
from cve_bin_tool.version import VERSION
from cve_bin_tool.version_scanner import VersionScanner
from cve_bin_tool.vex_manager.parse import VEXParse

sys.excepthook = excepthook  # Always install excepthook for entrypoint module.


class StringToListAction(argparse.Action):
    """Convert comma-separated strings to lists."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Parse and convert comma-separated values to a list."""
        values = list(map(lambda val: val.strip(), values.split(",")))
        setattr(namespace, self.dest, values)


def main(argv=None):
    """Scan a binary file for certain open source libraries that may have CVEs"""
    if sys.version_info < (3, 8):
        raise OSError(
            "Python no longer provides security updates for version 3.7 as of June 2023. Please upgrade to python 3.8+ to use CVE Binary Tool."
        )
    argv = argv or sys.argv

    # Reset logger level to info
    LOGGER.setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        prog="cve-bin-tool",
        description=textwrap.dedent(
            """
            The CVE Binary Tool scans for a number of common, vulnerable open source
            components (openssl, libpng, libxml2, libexpat and a few others) to let you know
            if a given directory or binary file includes common libraries with known
            vulnerabilities.
            """
        ),
        epilog=textwrap.fill(
            f'Available checkers: {", ".join(VersionScanner.available_checkers())}'
        )
        + "\n\n"
        + textwrap.fill(
            f'Available data sources: {", ".join(DataSourceSupport.available_data_sources())}'
        )
        + "\n\n"
        + textwrap.fill(
            f'Available language scanners: {", ".join(VersionScanner.available_language_checkers())}'
        )
        + "\n\nPlease disclose issues responsibly!",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    data_sources_group = parser.add_argument_group(
        "CVE Data Download", "Arguments related to data sources and Cache Configuration"
    )
    data_sources_group.add_argument(
        "-n",
        "--nvd",
        action="store",
        choices=["api", "api2", "json", "json-mirror", "json-nvd"],
        help="choose method for getting CVE lists from NVD",
        default="json-mirror",
    )
    data_sources_group.add_argument(
        "-u",
        "--update",
        action="store",
        choices=["now", "daily", "never", "latest"],
        help="update schedule for data sources and exploits database (default: daily)",
        default="daily",
    )
    data_sources_group.add_argument(
        "--nvd-api-key",
        action="store",
        default="",
        help=textwrap.dedent(
            """\
            Specify NVD API key (used to improve NVD rate limit).
            Set to `no` to ignore any keys in the environment.
            """
        ),
    )
    data_source_disable_help = f'comma-separated list of data sources ({", ".join(DataSourceSupport.available_data_sources())}) to disable (default: NONE)'
    data_sources_group.add_argument(
        "-d",
        "--disable-data-source",
        action=StringToListAction,
        help=data_source_disable_help,
        default=[],
    )
    data_sources_group.add_argument(
        "--use-mirror",
        action="store",
        help="use an mirror to update the database",
        default="",
    )

    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "directory", help="directory to scan", nargs="?", default=""
    )
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        default="",
        help="provide input filename",
    )
    input_group.add_argument(
        "-C", "--config", action="store", default="", help="provide config file"
    )
    input_group.add_argument(
        "-L", "--package-list", action="store", default="", help="provide package list"
    )
    input_group.add_argument(
        "--sbom",
        action="store",
        default="",
        choices=["spdx", "cyclonedx", "swid"],
        help="specify type of software bill of materials (sbom) (default: spdx)",
    )
    input_group.add_argument(
        "--sbom-file",
        action="store",
        help="provide sbom filename",
        default="",
    )
    input_group.add_argument(
        "--vex-file",
        action="store",
        help="provide vulnerability exchange (vex) filename for triage processing",
        default="",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress output",
        default=False,
    )
    output_group.add_argument(
        "-l",
        "--log",
        help="log level (default: info)",
        dest="log_level",
        action="store",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
    )
    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        help="provide output filename (default: output to stdout)",
        default="",
    )
    output_group.add_argument(
        "--html-theme",
        action="store",
        help="provide custom theme directory for HTML Report",
        default="",
    )
    output_group.add_argument(
        "-f",
        "--format",
        action="store",
        help=textwrap.dedent(
            """\
            update output format (default: console)
            specify multiple output formats by using comma (',') as a separator
            note: don't use spaces between comma (',') and the output formats.
            """
        ),
        metavar="{csv,json,json2,console,html,pdf}",
        default="console",
    )
    output_group.add_argument(
        "--generate-config",
        action="store",
        default="",
        choices=["yaml", "toml", "yaml,toml", "toml,yaml"],
        help="generate config file for cve bin tool in toml and yaml formats.",
    )
    output_group.add_argument(
        "-c",
        "--cvss",
        action="store",
        help="minimum CVSS score (as integer in range 0 to 10) to report (default: 0)",
        default=0,
    )
    output_group.add_argument(
        "-S",
        "--severity",
        action="store",
        choices=["low", "medium", "high", "critical"],
        help="minimum CVE severity to report (default: low)",
        default="low",
    )
    output_group.add_argument(
        "--metrics",
        action="store_true",
        help="check for metrics (e.g., EPSS) from found cves",
        default=False,
    )
    output_group.add_argument(
        "--epss-percentile",
        action="store",
        help="minimum epss percentile of CVE range between 0 to 100 to report. Automatically enables `--metrics`",
    )
    output_group.add_argument(
        "--epss-probability",
        action="store",
        help="minimum epss probability of CVE range between 0 to 100 to report. Automatically enables `--metrics`",
    )
    output_group.add_argument(
        "--no-0-cve-report",
        action="store_true",
        help="only produce report when CVEs are found",
        default=False,
    )
    output_group.add_argument(
        "-A",
        "--available-fix",
        action="store",
        nargs="?",
        const="local",
        choices=get_available_fix_supported_distros(),
        metavar="<distro_name>-<distro_version_name>",
        help="Lists available fixes of the package from Linux distribution",
        default="",
    )
    output_group.add_argument(
        "-b",
        "--backport-fix",
        action="store",
        nargs="?",
        const="local",
        choices=get_backport_supported_distros(),
        metavar="<distro_name>-<distro_version_name>",
        help="Lists backported fixes if available from Linux distribution",
        default="",
    )
    output_group.add_argument(
        "--affected-versions",
        action="count",
        default=0,
        help="Lists versions of product affected by a given CVE (to facilitate upgrades)",
    )

    output_group.add_argument(
        "--sbom-output",
        action="store",
        help="Provide software bill of materials (sbom) filename to generate",
        default="",
    )
    output_group.add_argument(
        "--sbom-type",
        action="store",
        default="spdx",
        choices=["spdx", "cyclonedx"],
        help="specify type of software bill of materials (sbom) to generate (default: spdx)",
    )
    output_group.add_argument(
        "--sbom-format",
        action="store",
        default="tag",
        choices=["tag", "json", "yaml"],
        help="specify format of software bill of materials (sbom) to generate (default: tag)",
    )
    vex_output_group = parser.add_argument_group(
        "Vex Output", "Arguments related to Vex output document."
    )
    vex_output_group.add_argument(
        "--vex-output",
        action="store",
        help="Provide vulnerability exchange (vex) filename to generate",
        default="",
    )
    vex_output_group.add_argument(
        "--vex-type",
        action="store",
        default="",
        choices=["cyclonedx", "csaf", "openvex"],
        help="specify type of vulnerability exchange (vex) to generate (default: cyclonedx)",
    )
    vex_output_group.add_argument(
        "--product",
        action="store",
        default="",
        help="Product Name",
    )
    vex_output_group.add_argument(
        "--release",
        action="store",
        default="",
        help="Release Version",
    )
    vex_output_group.add_argument(
        "--vendor",
        action="store",
        default="",
        help="Vendor/Supplier of Product",
    )
    vex_output_group.add_argument(
        "-rr",
        "--revision-reason",
        action="store",
        default="",
        help="a reason for the update to the vex document should be specified in double quotes",
    )
    vex_output_group.add_argument(
        "--filter-triage",
        action="store_true",
        default=False,
        help="Filter cves based on triage data from Vex file",
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action=StringToListAction,
        help="Comma separated Exclude directory path",
        default=[],
    )
    parser.add_argument("-V", "--version", action="version", version=VERSION)
    parser.add_argument(
        "--disable-version-check",
        action="store_true",
        help="skips checking for a new version",
        default=False,
    )
    parser.add_argument(
        "--disable-validation-check",
        action="store_true",
        help="skips checking xml files against schema",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="operate in offline mode",
        default=False,
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="add CVE description in csv or json report (no effect on console, html or pdf)",
        default=False,
    )

    merge_report_group = parser.add_argument_group(
        "Merge Report", "Arguments related to Intermediate and Merged Reports"
    )
    merge_report_group.add_argument(
        "-a",
        "--append",
        nargs="?",
        const=True,
        help="save output as intermediate report in json format",
        default=False,
    )
    merge_report_group.add_argument(
        "-t",
        "--tag",
        action="store",
        help="add a unique tag to differentiate between multiple intermediate reports",
        default="",
    )
    merge_report_group.add_argument(
        "-m",
        "--merge",
        action=StringToListAction,
        help="comma separated intermediate reports path for merging",
        default=None,
    )
    merge_report_group.add_argument(
        "-F",
        "--filter",
        action=StringToListAction,
        help="comma separated tag string for filtering intermediate reports",
        default=[],
    )

    checker_group = parser.add_argument_group("Checkers")
    checker_group.add_argument(
        "-s",
        "--skips",
        dest="skips",
        action=StringToListAction,
        type=str,
        help="comma-separated list of checkers to disable",
        default="",
    )
    checker_group.add_argument(
        "-r",
        "--runs",
        dest="runs",
        action=StringToListAction,
        type=str,
        help="comma-separated list of checkers to enable",
        default="",
    )

    database_group = parser.add_argument_group("Database Management")
    database_group.add_argument(
        "--import-json",
        action="store",
        help="import database from json files chopped by years",
        default="",
    )
    database_group.add_argument(
        "--ignore-sig",
        action="store_true",
        help="do not verify PGP signature while importing json data",
        default=False,
    )
    database_group.add_argument(
        "--log-signature-error",
        action="store_true",
        help="when the signature doesn't match log the error only instead of halting (UNSAFE)",
        default=False,
    )
    database_group.add_argument(
        "--verify",
        action="store",
        metavar="PGP_PUBKEY_PATH",
        help="verify PGP sign while importing json files",
        default="",
    )
    database_group.add_argument(
        "--export-json",
        action="store",
        help="export database as json files chopped by years",
        default="",
    )
    database_group.add_argument(
        "--pgp-sign",
        action="store",
        metavar="PGP_PRIVATE_KEY_PATH",
        help="sign exported json files with PGP",
        default="",
    )
    database_group.add_argument(
        "--passphrase",
        action="store",
        help="required passphrase for signing with PGP",
        default="",
    )
    database_group.add_argument(
        "--export",
        action="store",
        help="export database filename",
        default="",
    )
    database_group.add_argument(
        "--import",
        action="store",
        help="import database filename",
        default="",
    )

    exploit_checker_group = parser.add_argument_group("Exploits")
    exploit_checker_group.add_argument(
        "--exploits",
        action="store_true",
        help="check for exploits from found cves",
        default=False,
    )

    deprecated_group = parser.add_argument_group("Deprecated")
    deprecated_group.add_argument(
        "--triage-input-file",
        action="store",
        help="replaced by --vex-file",
        default="",
    )

    deprecated_group.add_argument(
        "-x",
        "--extract",
        action="store_true",
        help="autoextract compressed files",
        default=True,
    )
    deprecated_group.add_argument(
        "--report",
        action="store_true",
        help="Produces a report even if there are no CVE for the respective output format",
        default=False,
    )

    with ErrorHandler(mode=ErrorMode.NoTrace):
        raw_args = parser.parse_args(argv[1:])
        args = {key: value for key, value in vars(raw_args).items() if value}
        defaults = {key: parser.get_default(key) for key in vars(raw_args)}

    configs = {}
    if args.get("config"):
        conf = ConfigParser(args["config"])
        configs = conf.parse_config()

    args = ChainMap(args, configs, defaults)
    organized_arguments = {}
    if args["format"] == "json2" or args["generate_config"] != "":
        store = parser.parse_args(argv[1:])
        arg_groups = {}
        for grp in parser._action_groups:
            grp_dict = {
                a.dest: getattr(store, a.dest, None) for a in grp._group_actions
            }
            arg_groups[grp.title] = argparse.Namespace(**grp_dict)

        for group_title, group_args in arg_groups.items():
            group_title = group_title.replace(" ", "_")
            organized_arguments[group_title] = {}
            for arg_name, arg_value in vars(group_args).items():
                arg_name = arg_name.replace("_", "-")
                if arg_name == "log-level":
                    help_str = parser._option_string_actions["--log"].help
                elif arg_name == "directory":
                    help_str = "Directory to scan"
                else:
                    help_str = parser._option_string_actions[f"--{arg_name}"].help
                organized_arguments[group_title][arg_name] = {
                    "arg_value": arg_value,
                    "help": help_str,
                }

        LOGGER.debug(organized_arguments)
    # logging and error related settings
    if args["log_level"]:
        LOGGER.setLevel(args["log_level"].upper())

    if args["quiet"]:
        logging.disable(logging.ERROR)
        LOGGER.setLevel(logging.CRITICAL)

    if 0 < LOGGER.level <= 10:
        error_mode = ErrorMode.FullTrace
    elif LOGGER.level >= 50:
        error_mode = ErrorMode.NoTrace
    else:
        error_mode = ErrorMode.TruncTrace

    # once logging is set, we can output the version and NVD notice
    LOGGER.info(f"CVE Binary Tool v{VERSION}")
    LOGGER.info(
        "This product uses the NVD API but is not endorsed or certified by the NVD."
    )
    LOGGER.info(
        "For potentially faster NVD downloads, mirrors are available using -n json-mirror"
    )

    if args["nvd"] == "json":
        args["nvd"] = "json-mirror"
    nvd_type = args["nvd"]
    if nvd_type == "api":
        LOGGER.warning("API 1.0 is deprecated, switching to API 2.0")
        nvd_type = "api2"

    # If NVD API key is not set, check for environment variable (e.g. GitHub Secrets)
    if not args["nvd_api_key"] and os.getenv("nvd_api_key"):
        args["nvd_api_key"] = os.getenv("nvd_api_key")

    # Also try the uppercase env variable, in case people prefer those
    if not args["nvd_api_key"] and os.getenv("NVD_API_KEY"):
        args["nvd_api_key"] = os.getenv("NVD_API_KEY")

    # If you're not using an NVD key, let you know how to get one
    if nvd_type != "json-mirror" and not args["nvd_api_key"] and not args["offline"]:
        LOGGER.info("Not using an NVD API key. Your access may be rate limited by NVD.")
        LOGGER.info(
            "Get an NVD API key here: https://nvd.nist.gov/developers/request-an-api-key"
        )

    if nvd_type == "json-nvd":
        LOGGER.warning("Using legacy JSON interface.")
        LOGGER.warning(
            "You may want to switch to using cve-bin-tool's mirrors using -n json-mirror"
        )

    if platform.system() != "Linux":
        warning_nolinux = """
                          **********************************************
                          Warning: this utility was developed for Linux.
                          You may need to install additional utilities
                          to use it on other operating systems.
                          **********************************************
                          """
        LOGGER.warning(warning_nolinux)

    # warning about deprecated "--triage-input-file" argument
    if args["triage_input_file"]:
        LOGGER.error(
            " --triage-input-file has been deprecated. Please use --vex-file in future."
        )
        args["vex_file"] = args["triage_input_file"]
        if args["vex_file"].endswith(".vex"):
            # Auto-switch it to .json
            LOGGER.error(".vex extension no longer supported, please use .json")

            file_copy = Path(args["vex_file"] + ".cve-bin-tool-auto.json")
            original_file = Path(args["vex_file"])
            if not file_copy.exists():
                LOGGER.error("Trying to make a copy with .json extension for this run.")
                LOGGER.error("You will need to use this copy in future scans.")
                shutil.copy(original_file, file_copy)
                args["vex_file"] = str(file_copy)
            else:
                # abort and let the user deal with it
                LOGGER.error(
                    "Looks like a previous run of cve-bin-tool already made a copy."
                )
                LOGGER.error(f"Try re-running with --vex-file {file_copy}")
                return ERROR_CODES[VEXError]

    # CSVScanner related settings
    score = 0
    if args["severity"]:
        # Set minimum CVSS score based on severity
        cvss_score = {"low": 0, "medium": 4, "high": 7, "critical": 9}
        score = cvss_score[args["severity"]]
    if int(args["cvss"]) > 0:
        score = int(args["cvss"])

    metrics = args["metrics"]
    if args["epss_percentile"] or args["epss_probability"]:
        metrics = True

    epss_percentile = 0
    if (
        args["epss_percentile"]
        and float(args["epss_percentile"]) >= 0
        and float(args["epss_percentile"]) <= 100
    ):
        epss_percentile = float(args["epss_percentile"]) / 100
        LOGGER.debug(f"epss percentile stored {epss_percentile}")
    elif args["epss_percentile"]:
        LOGGER.debug(
            f'epss percentile {args["epss_percentile"]} is invalid so set it to 0'
        )

    epss_probability = 0
    if (
        args["epss_probability"]
        and float(args["epss_probability"]) >= 0
        and float(args["epss_probability"]) <= 100
    ):
        epss_probability = float(args["epss_probability"]) / 100
        LOGGER.debug(f"epss probability stored {epss_probability}")
    elif args["epss_probability"]:
        LOGGER.debug(
            f'epss probability {args["epss_probability"]} is invalid so set it to 0'
        )

    if args["generate_config"] != "":
        config_formats = set(args["generate_config"].split(","))
        config_formats = [config_format.strip() for config_format in config_formats]
        # current format includes .yaml and .toml
        for config_format in config_formats:
            LOGGER.debug(f"Arguments declared in generating config file {args}")
            config_generator(config_format, organized_arguments)

        return 0

    # Offline processing
    if args["offline"]:
        # Override version check and database update arguments
        version_check = True
        db_update = "never"
        incremental_db_update = False
    else:
        version_check = args["disable_version_check"]
        db_update = args["update"]
        incremental_db_update = True

    # list of sources that can be disabled but are not disabled
    # Data Source Processing
    # Ensure data source names are all upper case before validating list
    disable_data_sources = [d.upper() for d in args["disable_data_source"]]
    # Validate data source choices
    data_sources = DataSourceSupport()
    valid_data_sources = data_sources.get_data_sources()
    disabled_sources = []
    if len(disable_data_sources) > 0:
        LOGGER.debug(f"Processing disabled data sources {disable_data_sources}")
        for data_source in disable_data_sources:
            if data_source not in valid_data_sources:
                LOGGER.warning(
                    f"Argument --disable-data-source: invalid choice: {data_source} (choose from {valid_data_sources})"
                )
            else:
                LOGGER.info(f"Disabling data source {data_source}")
                disabled_sources.append(data_source)
        LOGGER.debug(f"Accepted disabled data sources {disabled_sources}")

    # Maintain list of sources that are used
    enabled_sources = []

    if "OSV" not in disabled_sources:
        source_osv = osv_source.OSV_Source(incremental_update=incremental_db_update)
        enabled_sources.append(source_osv)

    if "GAD" not in disabled_sources:
        source_gad = gad_source.GAD_Source(
            incremental_update=incremental_db_update,
        )
        enabled_sources.append(source_gad)

    if "REDHAT" not in disabled_sources:
        source_redhat = redhat_source.REDHAT_Source(
            incremental_update=incremental_db_update
        )
        enabled_sources.append(source_redhat)

    if "CURL" not in disabled_sources:
        source_curl = curl_source.Curl_Source()
        enabled_sources.append(source_curl)

    if "PURL2CPE" not in disabled_sources:
        source_purl2cpe = purl2cpe_source.PURL2CPE_Source()
        enabled_sources.append(source_purl2cpe)

    if "EPSS" not in disabled_sources:
        source_epss = epss_source.Epss_Source()
        enabled_sources.append(source_epss)

    if "NVD" not in disabled_sources:
        source_nvd = nvd_source.NVD_Source(
            nvd_type=nvd_type,
            incremental_update=incremental_db_update,
            nvd_api_key=args["nvd_api_key"],
            error_mode=error_mode,
        )
        enabled_sources = [source_nvd] + enabled_sources

    # Database update related settings
    # Connect to the database
    cvedb_orig = CVEDB(
        sources=enabled_sources,
        version_check=not version_check,
        error_mode=error_mode,
    )

    # if OLD_CACHE_DIR (from cvedb.py) exists, print warning
    if Path(OLD_CACHE_DIR).exists():
        LOGGER.warning(
            f"Obsolete cache dir {OLD_CACHE_DIR} is no longer needed and can be removed."
        )

    # Check database exists if operating in offline mode.
    if args["offline"] and not cvedb_orig.check_db_exists():
        LOGGER.critical("Database does not exist.")
        LOGGER.info(
            "Consult the documentation at https://cve-bin-tool.readthedocs.io/en/latest/how_to_guides/offline.html to find out how to setup offline operation."
        )
        return ERROR_CODES[CVEDBNotExist]

    if args["use_mirror"] and not args["offline"]:
        if (
            cvedb_orig.fetch_from_mirror(
                mirror=args["use_mirror"],
                pubkey=args["verify"],
                ignore_signature=args["ignore_sig"],
                log_signature_error=args["log_signature_error"],
            )
            == -1
        ):
            return ERROR_CODES[MirrorError]

    # import database from JSON chopped by years
    if args["import_json"] and cvedb_orig.check_db_exists():
        return_code = cvedb_orig.json_to_db_wrapper(
            path=args["import_json"],
            pubkey=args["verify"],
            ignore_signature=args["ignore_sig"],
            log_signature_error=args["log_signature_error"],
        )
        # And terminate operation
        return return_code

    # Export database as JSON chopped by years
    if args["export_json"] and cvedb_orig.check_db_exists():
        return_code = cvedb_orig.db_to_json(
            path=args["export_json"],
            private_key=args["pgp_sign"],
            passphrase=args["passphrase"],
        )
        # And terminate operation
        return return_code

    # Import database if file exists
    if args["import"] and Path(args["import"]).exists():
        LOGGER.info(f'Import database from {args["import"]}')
        cvedb_orig.copy_db(filename=args["import"], export=False)

    # Export database if database exists
    if args["export"] and cvedb_orig.check_db_exists():
        LOGGER.info(f'Export database to {args["export"]}')
        cvedb_orig.copy_db(filename=args["export"], export=True)
        # And terminate operation
        return 0

    # Clear data if -u now is set
    if db_update == "now":
        cvedb_orig.clear_cached_data()

    if db_update == "latest":
        cvedb_orig.refresh_cache_and_update_db()

    # update db if needed
    if db_update != "never":
        cvedb_orig.get_cvelist_if_stale()
    else:
        LOGGER.warning("Not verifying CVE DB cache")
        if not cvedb_orig.check_cve_entries():
            with ErrorHandler(mode=error_mode, logger=LOGGER):
                raise EmptyCache(cvedb_orig.cachedir)
        if not cvedb_orig.latest_schema():
            LOGGER.critical("Database does not have the latest schema.")
            LOGGER.info("Please update database, by using --update 'now'")
            if args["offline"]:
                LOGGER.info(
                    "Consult the documentation at https://cve-bin-tool.readthedocs.io/en/latest/how_to_guides/offline.html to find out how to setup offline operation."
                )
            return ERROR_CODES[CVEDBOutdatedSchema]

    # CVE Database validation
    if not cvedb_orig.check_cve_entries():
        with ErrorHandler(mode=error_mode, logger=LOGGER):
            raise CVEDataMissing("No data in CVE Database")

    # Report time of last database update
    db_date = time.strftime(
        "%d %B %Y at %H:%M:%S", time.localtime(cvedb_orig.get_db_update_date())
    )
    LOGGER.info(
        "CVE database contains CVEs from National Vulnerability Database (NVD), Open Source Vulnerability Database (OSV), Gitlab Advisory Database (GAD) and RedHat"
    )
    LOGGER.info(f"CVE database last updated on {db_date}")

    cvedb_orig.remove_cache_backup()

    output_formats = set(args["format"].split(","))
    output_formats = [output_format.strip() for output_format in output_formats]
    extensions = ["csv", "json", "console", "html", "pdf", "json2"]
    for output_format in output_formats:
        if output_format not in extensions:
            LOGGER.error(
                f"Argument -f/--format: invalid choice: {output_format} (choose from 'csv', 'json', 'console', 'html', 'pdf')"
            )
            return ERROR_CODES[InvalidExtensionError]

    # Check for PDF support
    if "pdf" in output_formats and importlib.util.find_spec("reportlab") is None:
        LOGGER.error("PDF output not available.")
        LOGGER.error(
            "If you want to produce PDF output, please install reportlab using pip install reportlab"
        )
        output_formats.remove("pdf")
        if len(output_formats) < 1:
            # If there's no other formats selected, exit so people actually see the error
            return ERROR_CODES[PDFOutputUnavailable]

    merged_reports = None
    if args["merge"]:
        LOGGER.info(
            "You can use -f --format and -o --output-file for saving merged intermediate reports in a file"
        )
        merged_reports = MergeReports(
            merge_files=args["merge"], score=score, filter_tag=args["filter"]
        )
        if args["input_file"]:
            LOGGER.warning(
                "Ignoring -i --input-file while merging intermediate reports"
            )
            args["input_file"] = None
        merge_cve_scanner = merged_reports.merge_intermediate()
    elif args["filter"] and not args["merge"]:
        LOGGER.warning(
            "Use -F --filter only when you want to filter out intermediate reports on the basis of tag"
        )

    # Input validation
    if (
        not args["directory"]
        and not args["input_file"]
        and not args["package_list"]
        and not args["merge"]
        and not args["sbom_file"]
        and not args["vex_file"]
    ):
        parser.print_usage()
        with ErrorHandler(logger=LOGGER, mode=ErrorMode.NoTrace):
            raise InsufficientArgs(
                "Please specify a directory to scan or an input file required"
            )

    # Output validation
    if not args["append"] and args["tag"]:
        LOGGER.warning(
            "Please specify -a --append to generate intermediate reports while using -t --tag"
        )

    if args["directory"] and not Path(args["directory"]).exists():
        parser.print_usage()
        with ErrorHandler(logger=LOGGER, mode=ErrorMode.NoTrace):
            raise FileNotFoundError("Directory/File doesn't exist")

    # Checkers related settings
    skips = args["skips"]
    if args["runs"]:
        runs = args["runs"]
        skips = list(
            map(
                lambda checker_name: checker_name,
                filter(
                    lambda checker_name: checker_name not in runs,
                    VersionScanner.available_checkers(),
                ),
            )
        )

    if (
        not args["input_file"]
        and args["directory"]
        and Path(args["directory"]).is_file()
    ):
        type = sbom_detection(args["directory"])
        if not args["sbom_file"] and not args["sbom"] and type is not None:
            LOGGER.info("Using CVE Binary Tool SBOM Auto Detection")
            args["sbom"] = type
            args["sbom_file"] = args["directory"]
            args["directory"] = ""

        elif (
            args["directory"].endswith(".csv")
            or args["directory"].endswith(".json")
            or args["directory"].endswith(".vex")
        ):
            args["input_file"] = args["directory"]
            args["directory"] = ""
            LOGGER.warning(
                "File specified is not a binary file and will be scanned as a bill of materials."
            )
            LOGGER.warning(
                "Specify --input_file to avoid this warning in future scans."
            )

    if (
        args["input_file"]
        and not args["input_file"].endswith(".csv")
        and not args["input_file"].endswith(".json")
    ):
        args["directory"] = args["input_file"]
        args["input_file"] = ""
        LOGGER.warning(
            "File specified is not a bill of materials and will be scanned as a binary file."
        )
        LOGGER.warning(
            "Remove --input_file when scanning binary files to avoid this warning in future scans."
        )

    # Fetching exploits from db to check for presence
    if args["exploits"]:
        cvedb_orig.get_cache_exploits()

    # Root package for generated SBOM. Will be updated to reflect input data
    sbom_root = "CVE-SCAN"

    with CVEScanner(
        score=score,
        check_metrics=metrics,
        epss_percentile=epss_percentile,
        epss_probability=epss_probability,
        check_exploits=args["exploits"],
        exploits_list=cvedb_orig.get_exploits_list(),
        disabled_sources=disabled_sources,
    ) as cve_scanner:
        triage_data: TriageData
        total_files: int = 0
        parsed_data: dict[ProductInfo, TriageData] = {}
        vex_product_info: dict[str, str] = {}
        sbom_serial_number = ""
        # Package List parsing
        if args["package_list"]:
            sbom_root = args["package_list"]
            package_list = PackageListParser(
                args["package_list"], error_mode=error_mode
            )
            parsed_data = package_list.parse_list()
            for product_info, triage_data in parsed_data.items():
                LOGGER.debug(f"{product_info}, {triage_data}")
                cve_scanner.get_cves(product_info, triage_data)

        if args["input_file"]:
            input_engine = InputEngine(
                args["input_file"], logger=LOGGER, error_mode=error_mode
            )
            parsed_data = input_engine.parse_input()
            if not args["directory"]:
                for product_info, triage_data in parsed_data.items():
                    LOGGER.debug(f"{product_info}, {triage_data}")
                    cve_scanner.get_cves(product_info, triage_data)
        if args["directory"]:
            sbom_root = args["directory"]
            version_scanner = VersionScanner(
                should_extract=args["extract"],
                exclude_folders=args["exclude"],
                error_mode=error_mode,
                validate=not args["disable_validation_check"],
                sources=enabled_sources,
            )
            version_scanner.remove_skiplist(skips)
            LOGGER.info(f"Number of checkers: {version_scanner.number_of_checkers()}")
            version_scanner.print_checkers()
            LOGGER.debug(
                "If the checkers aren’t loading properly: https://cve-bin-tool.readthedocs.io/en/latest/CONTRIBUTING.html#help-my-checkers-aren-t-loading"
            )
            LOGGER.info(
                f"Number of language checkers: {version_scanner.number_of_language_checkers()}"
            )
            version_scanner.print_language_checkers()

            for scan_info in version_scanner.recursive_scan(args["directory"]):
                if scan_info:
                    product_info, path = scan_info
                    LOGGER.debug(f"{product_info}: {path}")
                    # add product_info to parsed_data to check for with vex file
                    if product_info in parsed_data:
                        # update the paths in triage_data with the new path
                        triage_data = parsed_data[product_info]
                        triage_data["paths"].add(path)
                    else:
                        # create a new entry if product_info not in parsed_data
                        triage_data = {"default": {}, "paths": {path}}
                        parsed_data[product_info] = triage_data

                    cve_scanner.get_cves(product_info, triage_data)
            total_files = version_scanner.total_scanned_files

        if args["merge"]:
            cve_scanner = merge_cve_scanner

        if args["sbom_file"]:
            sbom_root = args["sbom_file"]
            # Process SBOM file
            sbom_list = SBOMParse(
                args["sbom_file"],
                sbom_type=args["sbom"],
                logger=LOGGER,
                validate=not args["disable_validation_check"],
            )
            parsed_data = sbom_list.parse_sbom()
            sbom_serial_number = sbom_list.serialNumber
            LOGGER.info(
                f"The number of products to process from SBOM - {len(parsed_data)}"
            )
            for product_info, triage_data in parsed_data.items():
                LOGGER.debug(f"{product_info}, {triage_data}")
                cve_scanner.get_cves(product_info, triage_data)

        if args["vex_file"]:
            # use auto so that lib4vex can auto-detect the vex type.
            vexdata = VEXParse(
                filename=args["vex_file"],
                vextype="auto",
                logger=LOGGER,
            )
            parsed_vex_data = vexdata.parse_vex()
            vex_product_info = vexdata.vex_product_info
            if not parsed_data:
                # assume the vex file being scanned is a standalone file
                args["filter_triage"] = False
                parsed_data = parsed_vex_data
                for product_info, triage_data in parsed_data.items():
                    LOGGER.debug(f"{product_info}, {triage_data}")
                    cve_scanner.get_cves(product_info, triage_data)
            else:
                LOGGER.info(
                    f"VEX file {args['vex_file']} is not a standalone file and will be used as a triage file"
                )
                # check weather vex is linked with given sbom or not.
                # only check cyclonedx since it have serialNumber.
                if (
                    args["sbom_file"]
                    and args["sbom"] == "cyclonedx"
                    and vexdata.vextype == "cyclonedx"
                    and sbom_serial_number not in vexdata.serialNumbers
                ):
                    LOGGER.warning(
                        f"SBOM file: {args['sbom_file']} is not linked to VEX file: {args['vex_file']}."
                    )
                for product_info, triage_data in parsed_vex_data.items():
                    LOGGER.debug(f"{product_info}, {triage_data}")
                    if product_info in parsed_data:
                        cve_scanner.get_cves(product_info, triage_data)
                    else:
                        LOGGER.info(
                            f"Product: {product_info.product} with Version: {product_info.version} not found in Parsed Data, is valid vex file being used?"
                        )

        LOGGER.info("Overall CVE summary: ")
        LOGGER.info(
            f"There are {cve_scanner.products_with_cve} products with known CVEs detected"
        )

        if cve_scanner.products_with_cve > 0 or args["report"]:
            affected_string = ", ".join(
                map(
                    lambda product_version: "".join(str(product_version)),
                    cve_scanner.affected(),
                )
            )
            LOGGER.info(f"Known CVEs in {affected_string}:")
        if args["vex_type"] or args["vex_output"]:
            # If vex_type is provided, then use it, else use cyclonedx as default vex_output should be provide in this case
            # If vex_output is provided, then use it, else use product, release and vendor to generate the vex file.
            if args["vex_output"] and not args["vex_type"]:
                # default vex_type is cyclonedx
                args["vex_type"] = "cyclonedx"
            if args["product"] and args["release"] and args["vendor"]:
                vex_product_info = {
                    "product": args["product"],
                    "release": args["release"],
                    "vendor": args["vendor"],
                    "revision_reason": args["revision_reason"],
                    "sbom_serial_number": sbom_serial_number,
                }
            elif args["vex_file"]:
                vex_product_info["revision_reason"] = args["revision_reason"]
            else:
                LOGGER.error(
                    "Please provide --product, --release and --vendor for VEX generation"
                )
                return ERROR_CODES[InsufficientArgs]

        if args["vex_file"] and args["filter_triage"]:
            cve_scanner.filter_triage_data()
        # Creates an Object for OutputEngine
        output = OutputEngine(
            all_cve_data=cve_scanner.all_cve_data,
            all_cve_version_info=cve_scanner.all_cve_version_info,
            all_product_data=cve_scanner.all_product_data,
            scanned_dir=args["directory"],
            filename=args["output_file"],
            themes_dir=args["html_theme"],
            time_of_last_update=cvedb_orig.time_of_last_update,
            tag=args["tag"],
            products_with_cve=cve_scanner.products_with_cve,
            products_without_cve=cve_scanner.products_without_cve,
            total_files=total_files,
            is_report=args["report"],
            no_zero_cve_report=args["no_0_cve_report"],
            append=args["append"],
            merge_report=merged_reports,
            affected_versions=args["affected_versions"],
            exploits=args["exploits"],
            metrics=metrics,
            organized_arguements=organized_arguments,
            detailed=args["detailed"],
            vex_filename=args["vex_output"],
            vex_type=args["vex_type"],
            vex_product_info=vex_product_info,
            sbom_filename=args["sbom_output"],
            sbom_type=args["sbom_type"],
            sbom_format=args["sbom_format"],
            sbom_root=sbom_root,
            offline=args["offline"],
        )

        if not args["quiet"]:
            output.output_file_wrapper(output_formats)
            if args["backport_fix"] or args["available_fix"]:
                distro_info = args["backport_fix"] or args["available_fix"]
                is_backport = True if args["backport_fix"] else False
                fixes = AvailableFixReport(
                    cve_scanner.all_cve_data, distro_info, is_backport
                )
                fixes.check_available_fix()

        # If no cves found, then the program exits cleanly (0 exit)
        if cve_scanner.products_with_cve == 0:
            return 0

        # if some cves are found, return with exit code 1
        # Previously this returned a number of CVEs found, but that can
        # exceed expected return value range.
        if cve_scanner.products_with_cve > 0:
            return 1

        # If somehow we got negative numbers of cves something has gone
        # horribly wrong.  Since return code 2 is used by argparse, use 3
        return 3


if __name__ == "__main__":
    if os.getenv("NO_EXIT_CVE_NUM"):
        main()
    else:
        sys.exit(main())
