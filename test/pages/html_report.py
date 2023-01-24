# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from os import unlink
from pathlib import Path
from tempfile import NamedTemporaryFile

from playwright.sync_api import Page

from cve_bin_tool.merge import MergeReports
from cve_bin_tool.output_engine.html import output_html
from cve_bin_tool.util import CVE, CVEData, ProductInfo, Remarks


class HTMLReport:
    MOCK_OUTPUT = {
        ProductInfo("vendor0", "product0", "1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1234",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    remarks=Remarks.NewFound,
                ),
                CVE(
                    "CVE-1234-1234",
                    "LOW",
                    score=1.2,
                    cvss_version=2,
                    cvss_vector="CVSS2.0/C:H",
                    remarks=Remarks.NewFound,
                ),
            ],
            paths={""},
        ),
        ProductInfo("vendor0", "product0", "2.8.6"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1234",
                    "LOW",
                    score=2.5,
                    cvss_version=3,
                    cvss_vector="CVSS3.0/C:H/I:L/A:M",
                    remarks=Remarks.Confirmed,
                )
            ],
            paths={""},
        ),
        ProductInfo("vendor1", "product1", "3.2.1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1234",
                    "HIGH",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    remarks=Remarks.Mitigated,
                )
            ],
            paths={""},
        ),
    }

    def __init__(self, page: Page):
        self.html_output = NamedTemporaryFile(
            "w+", delete=False, suffix=".html", encoding="utf-8"
        )

        logger = logging.getLogger()

        intermediate_report = MergeReports(
            merge_files=[
                str(Path(__file__).parent.resolve() / "json" / "test_intermediate.json")
            ],
        )
        intermediate_report.merge_intermediate()

        output_html(
            self.MOCK_OUTPUT,
            None,
            "",
            "",
            "",
            10,
            10,
            0,
            intermediate_report,
            logger,
            self.html_output,
        )

        self.page = page

        self.print_mode_button = page.locator("#printModeButton")
        self.interactive_mode_button = page.locator("#interactiveModeButton")
        self.print_mode_page = page.locator("#print_mode")
        self.interactive_mode_page = page.locator("#interactive_mode")

        self.modal_content = page.locator(".modal-content")
        self.product_rows = page.locator("#listProducts > a")
        self.modal_close_button = page.locator(".btn-close")
        self.vendor_product_pill = page.locator("#vendorProductPill")

        self.product_search_field = page.locator("#searchInput")

        self.new_cve_filter_button = page.locator("#filter-products :text('New')")
        self.confirmed_cve_filter_button = page.locator(
            "#filter-products :text('Confirmed')"
        )
        self.mitigated_cve_filter_button = page.locator(
            "#filter-products :text('Mitigated')"
        )

        self.cve_summary_table = page.locator("#cveSummary tbody tr")
        self.cve_remarks_table = page.locator("#cveRemarks tbody tr")

    def load(self) -> None:
        self.page.goto(f"file://{self.html_output.name}")

    def cleanup(self) -> None:
        self.html_output.close()
        unlink(self.html_output.name)

    def search_product(self, product: str) -> None:
        self.product_search_field.fill(product)
        self.page.evaluate("searchProductsScanned()")
