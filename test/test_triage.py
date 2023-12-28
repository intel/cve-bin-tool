# Copyright (C) 2022 Arnout Engelen
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import subprocess
import tempfile
from pathlib import Path

import pytest

TEMP_DIR = Path(tempfile.mkdtemp(prefix="requirements_scan-"))
TEST_DIR = Path(__file__).parent.resolve()
VEX_PATH = TEST_DIR / "vex"
CSV_PATH = TEST_DIR / "csv"
OUTPUT_JSON = str(TEMP_DIR / "test_triage_output.json")  # the output is a temp file


@pytest.mark.skip(reason="Temporarily disabled -- may need data changes")
def test_triage():
    INPUT_CSV = str(CSV_PATH / "test_triage_input.csv")
    TRIAGE_VEX = str(VEX_PATH / "test_triage_triage_input.vex")
    subprocess.run(
        [
            "python",
            "-m",
            "cve_bin_tool.cli",
            "--input-file",
            INPUT_CSV,
            "--triage-input-file",
            TRIAGE_VEX,
            "--format",
            "json",
            "--output-file",
            OUTPUT_JSON,
        ]
    )

    with open(OUTPUT_JSON) as f:
        output_json = json.load(f)
        # At least 1 CVEs as number of CVEs could change
        assert len(output_json) >= 1

        # Check output
        for output in output_json:
            if output["cve_number"] == "GMS-2016-69":
                # the triage file specifies the plotly error is mitigated
                assert output["remarks"] == "Mitigated"
            elif output["product"] == "aiohttp":
                # the triage file does not mention anything about aiohttp,
                # so that problem still needs to be reported as Unexplored:
                assert output["remarks"] == "Unexplored"
