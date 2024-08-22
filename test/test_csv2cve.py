# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from os.path import dirname, join

import pytest

import cve_bin_tool.csv2cve as csv2cve
from cve_bin_tool.error_handler import ERROR_CODES, InsufficientArgs


class TestCSV2CVE:
    @pytest.mark.asyncio
    async def test_csv2cve_valid_file(self, caplog):
        file_path = join(dirname(__file__), "csv", "triage.csv")

        csv2cve.main(["csv2cve", file_path])

        assert (
            "cve_bin_tool",
            logging.INFO,
            "There are 2 products with known CVEs detected",
        ) in caplog.record_tuples

        assert (
            "cve_bin_tool",
            logging.INFO,
            "Known CVEs in ('haxx.curl', '7.34.0'), ('mit.kerberos_5', '1.15.1'):",
        ) in caplog.record_tuples

        for cve_count, product in [
            [60, "haxx.curl version 7.34.0"],
            [9, "mit.kerberos_5 version 1.15.1"],
        ]:
            retrieved_cve_count = 0
            for captured_line in caplog.record_tuples:
                if captured_line[2].find(product) != -1:
                    retrieved_cve_count = int(captured_line[2].split()[0])

            assert retrieved_cve_count >= cve_count

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "args", (["csv2cve"], ["csv2cve", f"{dirname(__file__)}/txt/empty.txt"])
    )
    async def test_csv2cve_invalid_arguments(self, args):
        with pytest.raises(SystemExit) as e:
            csv2cve.main(args)
        assert e.value.args[0] == ERROR_CODES[InsufficientArgs]
