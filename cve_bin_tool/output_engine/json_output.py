# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from datetime import datetime
from typing import IO

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.util import CVEData, ProductInfo, VersionInfo
from cve_bin_tool.version import VERSION

from .util import format_output, get_cve_summary


def vulnerabilities_builder(
    all_cve_data, exploits, all_cve_version_info, detailed, affected_versions, metrics
):
    """
    Builds a dictionary of vulnerabilities based on the provided inputs.
    """
    vulnerabilities = {}
    vulnerabilities["summary"] = get_cve_summary(all_cve_data, exploits)
    vulnerability_reports = []
    source_entries_map = {}
    formatted_cve_data = format_output(
        all_cve_data, all_cve_version_info, detailed, affected_versions, metrics
    )
    for cve_entry in formatted_cve_data:
        source = cve_entry["source"]
        if source not in source_entries_map:
            source_entries_map[source] = [cve_entry]
        else:
            source_entries_map[source].append(cve_entry)

    for source, entries in source_entries_map.items():
        report = {"datasource": source, "entries": entries}
        vulnerability_reports.append(report)
    vulnerabilities["report"] = vulnerability_reports
    return vulnerabilities


def db_entries_count():
    """
    Retrieves the count of CVE entries from the database grouped by data source.

    Returns:
        dict: A dictionary containing the count of CVE entries for each data source.
    """
    instance = CVEDB()
    cursor = instance.db_open_and_get_cursor()
    cve_entries_check = "SELECT data_source, COUNT(*) as number FROM cve_severity GROUP BY data_source ORDER BY number DESC"
    cursor.execute(cve_entries_check)
    data_entries = {}
    rows = cursor.fetchall()
    for row in rows:
        source = row[0]
        entries = row[1]
        data_entries[source] = entries
    instance.db_close()
    return data_entries


def metadata_builder(organized_parameters):
    """
    Builds metadata dictionary based on the organized parameters.
    """
    metadata = {}
    metadata["tool"] = {"name": "cve-bin-tool", "version": f"{VERSION}"}
    metadata["generation_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parameter = {}
    for key, value in organized_parameters.items():
        parameter_values = {}
        for k, v in value.items():
            val = v["arg_value"]
            parameter_values[k] = val
        if parameter_values:
            parameter[key.lower()] = parameter_values
    metadata["parameter"] = parameter
    return metadata


def output_json(
    all_cve_data: dict[ProductInfo, CVEData],
    all_cve_version_info: dict[str, VersionInfo],
    outfile: IO,
    detailed: bool = False,
    affected_versions: int = 0,
    metrics: bool = False,
):
    """Output a JSON of CVEs"""
    formatted_output = format_output(
        all_cve_data, all_cve_version_info, detailed, affected_versions, metrics
    )
    json.dump(formatted_output, outfile, indent=2)


def output_json2(
    all_cve_data: dict[ProductInfo, CVEData],
    all_cve_version_info: dict[str, VersionInfo],
    time_of_last_update: datetime,
    outfile: IO,
    affected_versions: int,
    organized_parameters: dict,
    detailed: bool = False,
    exploits: bool = False,
    metrics: bool = False,
):
    """Output a JSON of CVEs in JSON2 format"""
    output = {}
    output["$schema"] = ""
    output["metadata"] = metadata_builder(organized_parameters)
    output["database_info"] = {
        "last_updated": time_of_last_update.strftime("%Y-%m-%d %H:%M:%S"),
        "total_entries": db_entries_count(),
    }
    output["vulnerabilities"] = vulnerabilities_builder(
        all_cve_data,
        exploits,
        all_cve_version_info,
        detailed,
        affected_versions,
        metrics,
    )
    json.dump(output, outfile, indent=2)
