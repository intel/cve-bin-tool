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
            "There are 3 products with known CVEs detected",
        ) in caplog.record_tuples

        assert (
            "cve_bin_tool",
            logging.INFO,
            "Known CVEs in ('curl', '7.34.0'), ('kerberos', '1.15.1'), ('kerberos_5', '1.15.1'):",
        ) in caplog.record_tuples

        for cve in [
            "3 CVE(s) in mit.kerberos v1.15.1",
            # "58 CVE(s) in haxx.curl v7.34.0", Seems to be changing right now
            "9 CVE(s) in mit.kerberos_5 v1.15.1",
        ]:
            assert (
                "cve_bin_tool.CVEScanner",
                logging.INFO,
                cve,
            ) in caplog.record_tuples

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "args", (["csv2cve"], ["csv2cve", f"{dirname(__file__)}/txt/empty.txt"])
    )
    async def test_csv2cve_invalid_arguments(self, args):
        with pytest.raises(SystemExit) as e:
            csv2cve.main(args)
        assert e.value.args[0] == ERROR_CODES[InsufficientArgs]
