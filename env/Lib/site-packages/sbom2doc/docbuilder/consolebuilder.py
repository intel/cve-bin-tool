# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sbom2doc.docbuilder.docbuilder import DocBuilder


class ConsoleBuilder(DocBuilder):
    def __init__(self):
        pass

    def heading(self, level, title, number=True):
        print(Panel(title, style="bold", expand=False))

    def paragraph(self, text):
        print(f"\n{text}")

    def createtable(self, header, validate=None):
        # Layout is [headings, ....]
        self.table = Table()
        for h in header:
            self.table.add_column(h)

    def addrow(self, data):
        if len(data) > 5:
            print("Ooops - too much data!")
        else:
            # Add row to table
            if len(data) == 1:
                self.table.add_row(data[0])
            elif len(data) == 2:
                self.table.add_row(data[0], data[1])
            elif len(data) == 3:
                self.table.add_row(data[0], data[1], data[2])
            elif len(data) == 4:
                self.table.add_row(data[0], data[1], data[2], data[3])
            else:
                self.table.add_row(data[0], data[1], data[2], data[3], data[4])

    def showtable(self, widths=None):
        console = Console()
        console.print(self.table)
