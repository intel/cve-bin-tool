# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import re

import pytest
from playwright.sync_api import Locator, Page, expect

from .pages.html_report import HTMLReport


class TestOutputHTML:
    @pytest.fixture(autouse=True)
    def setup_method(self, page: Page) -> None:
        self.html_report_page = HTMLReport(page)
        self.html_report_page.load()

    def teardown_method(self) -> None:
        self.html_report_page.cleanup()

    def check_products_visible_hidden(
        self, visible_row: Locator, *hidden_rows: Locator
    ) -> None:
        for i in range(visible_row.count()):
            expect(visible_row.nth(i)).to_be_visible()

        for hidden_row in hidden_rows:
            for i in range(hidden_row.count()):
                expect(hidden_row.nth(i)).to_be_hidden()

    def test_interactive_mode_print_mode_switching(self) -> None:
        """Test Interactive mode to hide and Print mode to be visible when clicked on "Print Mode Button"
        Expect Interactive mode to be visible and Print mode to hide when clicked on "Interactive Mode Button" """

        print_mode_button = self.html_report_page.print_mode_button
        print_mode_page = self.html_report_page.print_mode_page
        interactive_mode_button = self.html_report_page.interactive_mode_button
        interactive_mode_page = self.html_report_page.interactive_mode_page

        print_mode_button.click()
        expect(print_mode_page).to_be_visible()
        expect(interactive_mode_page).to_be_hidden()

        interactive_mode_button.click()
        expect(interactive_mode_page).to_be_visible()
        expect(print_mode_page).to_be_hidden()

    def test_modal_switching(self) -> None:
        """Test modal to be visible when clicked on the product row or the vendor_product pill
        and to be hidden when clicked on the close button"""

        modal_content = self.html_report_page.modal_content.nth(0)
        product_row = self.html_report_page.product_rows.nth(0)
        modal_close_button = self.html_report_page.modal_close_button.nth(0)
        vendor_product_pill = self.html_report_page.vendor_product_pill.nth(0)

        expect(modal_content).to_be_hidden()
        product_row.click()
        expect(modal_content).to_be_visible()
        modal_close_button.click()
        expect(modal_content).to_be_hidden()

        vendor_product_pill.click()
        expect(modal_content).to_be_visible()
        modal_close_button.click()
        expect(modal_content).to_be_hidden()

    def test_product_search(self) -> None:
        """Test Search function to filter the products"""

        product_rows = self.html_report_page.product_rows

        for i in range(product_rows.count()):
            expect(product_rows.nth(i)).to_be_visible()

        expect(product_rows).to_have_count(3)
        self.html_report_page.search_product("product0")

        filtered_row = product_rows.filter(
            has_text=re.compile(r"vendor0.*product0", flags=re.DOTALL)
        )
        unfiltered_row = product_rows.filter(has_text=re.compile(r"vendor1|product1"))
        self.check_products_visible_hidden(filtered_row, unfiltered_row)

    def test_product_remark_filter(self) -> None:
        """Test CVE product remark filters"""

        product_rows = self.html_report_page.product_rows

        new_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor0.*product0.*NEW.*1.0", flags=re.DOTALL)
        )
        confirmed_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor0.*product0.*2.8.6", flags=re.DOTALL)
        )
        mitigated_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor1.*product1.*3.2.1.0", flags=re.DOTALL)
        )

        new_cve_filter_button = self.html_report_page.new_cve_filter_button
        confirmed_cve_filter_button = self.html_report_page.confirmed_cve_filter_button
        mitigated_cve_filter_button = self.html_report_page.mitigated_cve_filter_button

        new_cve_filter_button.click()
        self.check_products_visible_hidden(
            new_cve_product_row, confirmed_cve_product_row, mitigated_cve_product_row
        )
        confirmed_cve_filter_button.click()
        self.check_products_visible_hidden(
            confirmed_cve_product_row, new_cve_product_row, mitigated_cve_product_row
        )
        mitigated_cve_filter_button.click()
        self.check_products_visible_hidden(
            mitigated_cve_product_row, new_cve_product_row, confirmed_cve_product_row
        )

    def test_cve_summary_table(self) -> None:
        """Test CVE Summary Table"""

        cve_summary_table = self.html_report_page.cve_summary_table
        expect(cve_summary_table).to_contain_text(["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_cve_remarks_table(self) -> None:
        """Test CVE Remarks Table"""

        cve_remarks_table = self.html_report_page.cve_remarks_table
        expect(cve_remarks_table).to_contain_text(
            ["NEW", "CONFIRMED", "MITIGATED", "UNEXPLORED", "IGNORED"]
        )
