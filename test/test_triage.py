# Copyright (C) 2022 Arnout Engelen
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import subprocess
import tempfile
from pathlib import Path

TEMP_DIR = Path(tempfile.mkdtemp(prefix="requirements_scan-"))
TEST_DIR = Path(__file__).parent.resolve()
VEX_PATH = TEST_DIR / "vex"
CSV_PATH = TEST_DIR / "csv"
OUTPUT_JSON = str(TEMP_DIR / "test_triage_output.json")  # the output is a temp file


class TestTriage:
    def test_json(self):
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
                if output["cve_number"] == "CVE-2023-46308":
                    # the triage file specifies the plotly error is mitigated
                    assert output["remarks"] == "NotAffected"
                    assert output["justification"] == "requires_environment"
                    assert output["response"] == ["will_not_fix"]
                    assert output["comments"] == "Detail field"
                else:
                    # the triage file does not mention any other vulnerability,
                    # so it still needs to be reported as Unexplored:
                    assert output["remarks"] == "Unexplored"
                    assert output.get("justification", None) is None
                    assert output.get("response", None) is None
                    assert output["comments"] == ""

    def test_vex(self):
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
                "--vex",
                OUTPUT_JSON,
            ]
        )

        with open(OUTPUT_JSON) as f:
            output_json = json.load(f)
            # At least 1 CVEs as number of CVEs could change
            assert len(output_json) >= 1

            # Check output
            for output in output_json["vulnerabilities"]:
                if output["id"] == "CVE-2023-46308":
                    # the triage file specifies the plotly error is mitigated
                    assert output["analysis"]["state"] == "not_affected"
                    assert output["analysis"]["justification"] == "requires_environment"
                    assert output["analysis"]["response"] == ["will_not_fix"]
                    assert output["analysis"]["detail"] == "NotAffected: Detail field"
                else:
                    # the triage file does not mention any other vulnerability,
                    # so it still needs to be reported as in triage:
                    assert output["analysis"]["state"] == "in_triage"
                    assert output["analysis"].get("justification", None) is None
                    assert output["analysis"]["response"] == []
                    assert output["analysis"]["detail"] == "Unexplored"
