# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import re

import pytest
from playwright.sync_api import Locator, Page, expect

from cve_bin_tool.util import CVE, CVEData, ProductInfo, Remarks

from .pages.html_report import HTMLReport


class TestOutputHTML:
    MOCK_OUTPUT = {
        ProductInfo("vendor0", "product0", "1.0", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1000",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    remarks=Remarks.NewFound,
                    comments="showup",
                ),
                CVE(
                    "CVE-1234-1001",
                    "LOW",
                    score=1.2,
                    cvss_version=2,
                    cvss_vector="CVSS2.0/C:H",
                    remarks=Remarks.NewFound,
                    comments="",
                ),
            ],
            paths={""},
        ),
        ProductInfo("vendor0", "product0", "2.8.6", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1002",
                    "LOW",
                    score=2.5,
                    cvss_version=3,
                    cvss_vector="CVSS3.0/C:H/I:L/A:M",
                    remarks=Remarks.Confirmed,
                    comments="",
                )
            ],
            paths={""},
        ),
        ProductInfo(
            "vendor1", "product1", "3.2.1.0", "/usr/local/bin/product"
        ): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1003",
                    "HIGH",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    remarks=Remarks.Mitigated,
                    comments="",
                )
            ],
            paths={""},
        ),
        ProductInfo(
            "vendor1", "product1", "4.2.1.0", "/usr/local/bin/product"
        ): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1004",
                    "HIGH",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    remarks=Remarks.Unexplored,
                    comments="",
                ),
            ],
            paths={""},
        ),
        ProductInfo(
            "vendor1", "product2", "5.2.1.0", "/usr/local/bin/product"
        ): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1005",
                    "HIGH",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    remarks=Remarks.FalsePositive,
                    comments="",
                ),
            ],
            paths={""},
        ),
        ProductInfo(
            "vendor1", "product3", "6.2.1.0", "/usr/local/bin/product"
        ): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1006",
                    "HIGH",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    remarks=Remarks.NotAffected,
                    comments="",
                )
            ],
            paths={""},
        ),
    }

    @pytest.fixture(autouse=True)
    def setup_method(self, page: Page) -> None:
        """Setup method for HTML Testing."""
        self.page = page
        self.html_report_page = HTMLReport(page, self.MOCK_OUTPUT)
        self.html_report_page.load()

    def teardown_method(self) -> None:
        """Teardown method for HTML Testing."""
        if hasattr(self, "html_report_page") and self.html_report_page is not None:
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
        Expect Interactive mode to be visible and Print mode to hide when clicked on "Interactive Mode Button"
        """

        print_mode_button = self.html_report_page.print_mode_button
        print_mode_page = self.html_report_page.print_mode_page
        interactive_mode_button = self.html_report_page.interactive_mode_button
        interactive_mode_page = self.html_report_page.interactive_mode_page

        print_mode_button.click()
        expect(print_mode_page).to_be_visible()
        expect(interactive_mode_page).to_be_hidden()
        expect(print_mode_page).to_contain_text("showup")

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
        expect(modal_content).to_contain_text("Comment: showup")
        modal_close_button.click()
        expect(modal_content).to_be_hidden()

    def test_product_search(self) -> None:
        """Test Search function to filter the products"""

        product_rows = self.html_report_page.product_rows

        for i in range(product_rows.count()):
            expect(product_rows.nth(i)).to_be_visible()

        expect(product_rows).to_have_count(6)
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
        unexplored_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor1.*product1.*4.2.1.0", flags=re.DOTALL)
        )
        false_positive_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor1.*product2.*5.2.1.0", flags=re.DOTALL)
        )
        not_affected_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor1.*product3.*6.2.1.0", flags=re.DOTALL)
        )

        new_cve_filter_button = self.html_report_page.new_cve_filter_button
        confirmed_cve_filter_button = self.html_report_page.confirmed_cve_filter_button
        mitigated_cve_filter_button = self.html_report_page.mitigated_cve_filter_button
        unexplored_cve_filter_button = (
            self.html_report_page.unexplored_cve_filter_button
        )
        false_positive_cve_filter_button = (
            self.html_report_page.false_positive_cve_filter_button
        )
        not_affected_cve_filter_button = (
            self.html_report_page.not_affected_cve_filter_button
        )

        new_cve_filter_button.click()
        self.check_products_visible_hidden(
            new_cve_product_row,
            confirmed_cve_product_row,
            mitigated_cve_product_row,
            unexplored_cve_product_row,
            false_positive_cve_product_row,
            not_affected_cve_product_row,
        )
        confirmed_cve_filter_button.click()
        self.check_products_visible_hidden(
            confirmed_cve_product_row,
            new_cve_product_row,
            mitigated_cve_product_row,
            unexplored_cve_product_row,
            false_positive_cve_product_row,
            not_affected_cve_product_row,
        )
        mitigated_cve_filter_button.click()
        self.check_products_visible_hidden(
            mitigated_cve_product_row,
            new_cve_product_row,
            confirmed_cve_product_row,
            unexplored_cve_product_row,
            false_positive_cve_product_row,
            not_affected_cve_product_row,
        )
        unexplored_cve_filter_button.click()
        self.check_products_visible_hidden(
            unexplored_cve_product_row,
            new_cve_product_row,
            confirmed_cve_product_row,
            mitigated_cve_product_row,
            false_positive_cve_product_row,
            not_affected_cve_product_row,
        )
        false_positive_cve_filter_button.click()
        self.check_products_visible_hidden(
            false_positive_cve_product_row,
            new_cve_product_row,
            confirmed_cve_product_row,
            mitigated_cve_product_row,
            unexplored_cve_product_row,
            not_affected_cve_product_row,
        )
        not_affected_cve_filter_button.click()
        self.check_products_visible_hidden(
            not_affected_cve_product_row,
            new_cve_product_row,
            confirmed_cve_product_row,
            mitigated_cve_product_row,
            unexplored_cve_product_row,
            false_positive_cve_product_row,
        )

    def test_cve_summary_table(self) -> None:
        """Test CVE Summary Table"""

        cve_summary_table = self.html_report_page.cve_summary_table
        expect(cve_summary_table).to_contain_text(["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_cve_remarks_table(self) -> None:
        """Test CVE Remarks Table"""

        cve_remarks_table = self.html_report_page.cve_remarks_table
        expect(cve_remarks_table).to_contain_text(
            [
                "NEW",
                "CONFIRMED",
                "MITIGATED",
                "UNEXPLORED",
                "FALSE POSITIVE",
                "NOT AFFECTED",
            ]
        )

    # Test for empty cve_data["cves"] list
    def test_empty_cve_list(self) -> None:
        """Test that the HTML report renders correctly with an empty cve_data["cves"] list."""
        empty_output = {
            ProductInfo("vendor0", "product0", "1.0", "usr/local/bin/product"): CVEData(
                cves=[],
                paths={""},
            )
        }
        if hasattr(self, "html_report_page") and self.html_report_page is not None:
            self.html_report_page.cleanup()  # Clean up the previous page
        self.html_report_page = HTMLReport(self.page, empty_output)
        self.html_report_page.load()
        product_rows = self.html_report_page.product_rows
        expect(product_rows).to_have_count(0)

    # Test for cve_data["cves"] list with an element containing "UNKNOWN" CVE number
    def test_unknown_cve_number(self) -> None:
        """Test that the HTML report renders correctly with a cve_data["cves"] list containing an 'UNKNOWN' CVE number."""
        unknown_cve_output = {
            ProductInfo("vendor0", "product0", "1.0", "usr/local/bin/product"): CVEData(
                cves=[
                    CVE(
                        "UNKNOWN",
                        "MEDIUM",
                        score=4.2,
                        cvss_version=2,
                        cvss_vector="C:H",
                        remarks=Remarks.NewFound,
                        comments="showup",
                    )
                ],
                paths={""},
            )
        }
        self.html_report_page.cleanup()  # Clean up the previous page
        self.html_report_page = HTMLReport(
            self.html_report_page.page, unknown_cve_output
        )
        self.html_report_page.load()
        product_rows = self.html_report_page.product_rows
        expect(product_rows).to_have_count(1)
