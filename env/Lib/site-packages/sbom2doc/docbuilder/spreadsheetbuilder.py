# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from openpyxl import Workbook
from openpyxl.styles import Font

from sbom2doc.docbuilder.docbuilder import DocBuilder


class SpreadsheetBuilder(DocBuilder):
    def __init__(self):
        self.workbook_document = Workbook()
        self.worksheet = self.workbook_document.active
        self.worksheet_data = []
        self.table_width = 0
        self.headingcount = 0
        self.heading_title = None

    def heading(self, level, title, number=True):
        self._flush_table()
        self.heading_title = title

    def _flush_table(self):
        if len(self.worksheet_data) > 0:
            # flush table
            self.showtable()

    def _heading(self, title):
        # Optionally create new worksheet
        sheet_title = f"{self.headingcount} - {title}"
        if self.headingcount > 0:
            self.worksheet = self.workbook_document.create_sheet(sheet_title)
            self.headingcount += 1
        else:
            # Name current sheet
            self.worksheet.title = title
            self.headingcount = 1
        self.workbook_document.active = self.worksheet
        self.worksheet_data = []

    def paragraph(self, text):
        if len(text) > 0:
            if self.table_width == 0:
                # Create pseudo table
                self.createtable(["Text"])
            self.worksheet_data.append([text])

    def createtable(self, header, validate=None):
        self._heading(self.heading_title)
        self.worksheet_data.append(header)
        self.table_width = len(header)

    def addrow(self, data):
        # Add row to table
        my_data = []
        for d in data:
            if d is not None:
                my_data.append(d)
            else:
                my_data.append("")
        self.worksheet_data.append(my_data)

    def showtable(self, widths=None):
        # Add data to current worksheet
        for data in self.worksheet_data:
            self.worksheet.append(data)
        # Now make first row Bold
        font = Font(bold=True)
        end_column = chr(ord("A") + self.table_width - 1)
        for row in self.worksheet[f"A1:{end_column}1"]:
            for cell in row:
                cell.font = font
        self.worksheet_data = []
        self.table_width = 0

    def publish(self, filename):
        self._flush_table()
        self.workbook_document.save(filename)
