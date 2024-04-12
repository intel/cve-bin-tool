# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToDict

import fuzz.generated.intermediate_report_pb2 as intermediate_report_pb2

with atheris.instrument_imports():
    from cve_bin_tool.merge import MergeReports


def TestParseData(data):
    """
    This function converts the given data into a IntermediateReport file and Fuzz tests the IntermediateReport's handling of IntermediateReport files.

    Args:
        data (protobuf message): The protobuf message to convert and process.
    """
    try:
        json_data = MessageToDict(
            data, preserving_proto_field_name=True, including_default_value_fields=True
        )

        if json_data.get("metadata") is not None:
            json_data["metadata"]["timestamp"] = datetime.fromtimestamp(
                abs(int(json_data["metadata"].get("timestamp", 0))) / 1e8
            ).strftime("%Y-%m-%d.%H-%M-%S")

        with open(file_path, "w") as f:
            json.dump(json_data, f)

        intermediate_report = MergeReports(merge_files=[file_path])
        intermediate_report.merge_intermediate()

    except SystemExit:
        return


file_path = str(
    Path(tempfile.mkdtemp(prefix="cve-bin-tool-FUZZ_INTERMEDIATE_REPORT"))
    / "test_intermediate.json"
)
atheris_libprotobuf_mutator.Setup(
    sys.argv, TestParseData, proto=intermediate_report_pb2.IntermediateReport
)
atheris.Fuzz()
