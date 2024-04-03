# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os

# from os import unlink
from pathlib import Path
from tempfile import NamedTemporaryFile

from playwright.sync_api import Page

from cve_bin_tool.merge import MergeReports
from cve_bin_tool.output_engine.html import output_html
from cve_bin_tool.util import CVEData, ProductInfo


class HTMLReport:
    def __init__(self, page: Page, all_cve_data: dict[ProductInfo, CVEData]):
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
            all_cve_data,
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
        self.unexplored_cve_filter_button = page.locator(
            "#filter-products :text('Unexplored')"
        )
        self.false_positive_cve_filter_button = page.locator(
            "#filter-products :text('False Positive')"
        )
        self.not_affected_cve_filter_button = page.locator(
            "#filter-products :text('Not Affected')"
        )

        self.cve_summary_table = page.locator("#cveSummary tbody tr")
        self.cve_remarks_table = page.locator("#cveRemarks tbody tr")

    def load(self) -> None:
        self.page.goto(f"file://{self.html_output.name}")

    def cleanup(self) -> None:
        """Cleanup method for HTMLReport."""
        # Close the HTML output file if it's open
        if self.html_output:
            self.html_output.close()

        # Remove the temporary HTML file if it exists
        if os.path.exists(self.html_output.name):
            os.unlink(self.html_output.name)

    def search_product(self, product: str) -> None:
        self.product_search_field.fill(product)
        self.page.evaluate("searchProductsScanned()")
