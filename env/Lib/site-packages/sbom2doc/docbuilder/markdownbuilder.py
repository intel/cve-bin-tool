# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from lib4sbom.output import SBOMOutput

from sbom2doc.docbuilder.docbuilder import DocBuilder


class MarkdownBuilder(DocBuilder):
    def __init__(self):
        self.markdown_document = []

    def heading(self, level, title, number=True):
        heading_field = "#" * level
        self.markdown_document.append(f"\n{heading_field} {title}\n")

    def paragraph(self, text):
        self.markdown_document.append(f"{text}")

    def createtable(self, header, validate=None):
        # Layout is [headings, ....]
        table_headings = " | ".join(h for h in header)
        table_header = "| -------- " * len(header)
        self.markdown_document.append(table_headings)
        self.markdown_document.append(table_header)

    def addrow(self, data):
        # Add row to table
        my_data = []
        for d in data:
            if d is not None:
                my_data.append(d)
            else:
                my_data.append("")
        table_row = " | ".join(d for d in my_data)
        self.markdown_document.append(table_row)

    def publish(self, filename):
        markdown_doc = SBOMOutput(filename=filename)
        markdown_doc.generate_output(self.markdown_document)
