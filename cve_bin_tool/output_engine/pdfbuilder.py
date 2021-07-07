# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle as PS
from reportlab.lib.units import cm
from reportlab.platypus import PageBreak, Spacer, TableStyle
from reportlab.platypus.doctemplate import (
    BaseDocTemplate,
    PageTemplate,
    SimpleDocTemplate,
)
from reportlab.platypus.frames import Frame
from reportlab.platypus.paragraph import Paragraph
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.platypus.tables import Table


class PDFDocTemplate(SimpleDocTemplate):
    def __init__(self, filename, **kw):
        self.allowSplitting = 0
        BaseDocTemplate.__init__(self, filename, **kw)
        template = PageTemplate(
            "normal", [Frame(2.5 * cm, 2.5 * cm, 15 * cm, 25 * cm, id="F1")]
        )
        self.addPageTemplates(template)

    def afterFlowable(self, flowable):
        "Registers TOC entries. and makes each TOC entry clickable"
        if flowable.__class__.__name__ == "Paragraph":
            text = flowable.getPlainText()
            style = flowable.style.name
            if style == "Heading1":
                key = "h1-%s" % self.seq.nextf("heading1")
                self.canv.bookmarkPage(key)
                self.notify("TOCEntry", (0, text, self.page, key))
            if style == "Heading2":
                key = "h2-%s" % self.seq.nextf("heading2")
                self.canv.bookmarkPage(key)
                self.notify("TOCEntry", (1, text, self.page, key))


class ConditionalSpacer(Spacer):
    def wrap(self, availWidth, availHeight):
        height = min(self.height, availHeight - 1e-8)
        return (availWidth, height)


class PDFBuilder:
    h1 = PS(name="Heading1", fontSize=16, fontName="Helvetica-Bold", leading=18)
    h2 = PS(name="Heading2", fontSize=14, fontName="Helvetica-Bold", leading=16)
    h3 = PS(name="Heading3", fontSize=12, fontName="Helvetica", leading=14)

    toc_h1 = PS(
        name="Heading1",
        fontSize=16,
        leftIndent=20,
        firstLineIndent=-20,
        spaceBefore=5,
        fontName="Helvetica-Bold",
        leading=18,
    )
    toc_h2 = PS(
        name="Heading2",
        fontSize=14,
        leftIndent=40,
        firstLineIndent=-20,
        spaceBefore=0,
        fontName="Helvetica-Bold",
        leading=16,
    )

    body = PS(name="body", fontSize=12, fontName="Helvetica", leading=12)

    body_unknown = PS(
        name="body",
        fontSize=12,
        textColor=colors.grey,
        fontName="Helvetica-Bold",
        leading=12,
    )

    body_low = PS(
        name="body",
        fontSize=12,
        textColor=colors.blue,
        fontName="Helvetica-Bold",
        leading=12,
    )

    body_medium = PS(
        name="body",
        fontSize=12,
        textColor=colors.green,
        fontName="Helvetica-Bold",
        leading=12,
    )

    body_high = PS(
        name="body",
        fontSize=12,
        textColor=colors.orange,
        fontName="Helvetica-Bold",
        leading=12,
    )

    body_critical = PS(
        name="body",
        fontSize=12,
        textColor=colors.red,
        fontName="Helvetica-Bold",
        leading=12,
    )

    spacer = ConditionalSpacer(0.25 * cm, 0.25 * cm)

    tblStyle = TableStyle(
        [
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.black),
            ("BOX", (0, 0), (-1, -1), 0.25, colors.black),
            ("FONT", (0, 0), (-1, -1), "Helvetica", 12),
            ("FONT", (0, 0), (5, 0), "Helvetica-Bold"),
        ]
    )

    frontPageStyle = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 20),
        ]
    )

    grey = colors.grey
    blue = colors.blue
    red = colors.red
    green = colors.green
    orange = colors.orange

    cm = cm

    def __init__(self, includeTOC=True):
        self.contents = []
        self.toc_included = includeTOC
        self.toc = TableOfContents()
        self.toc.levelStyles = [self.toc_h1, self.toc_h2]
        self.headingnumber = [0, 0, 0, 0]
        self.table_data = []
        self.note_data = []
        self.table_validation = None

    def _spacer(self):
        self.contents.append(self.spacer)

    def heading(self, level, title):
        self._spacer()
        if level == 1:
            self.headingnumber[level] += 1
            # Reset subheading number
            self.headingnumber[level + 1] = 0
            self.contents.append(
                Paragraph(str(self.headingnumber[level]) + ". " + title, self.h1)
            )
        elif level == 2:
            self.headingnumber[level] += 1
            # Reset subheading number
            self.headingnumber[level + 1] = 0
            self.contents.append(
                Paragraph(
                    str(self.headingnumber[level - 1])
                    + "."
                    + str(self.headingnumber[level])
                    + " "
                    + title,
                    self.h2,
                )
            )
        else:
            print("Ooops.... Level", level)
        self._spacer()

    def paragraph(self, text, style=None):
        if style is None:
            self.contents.append(Paragraph(text, self.body))
        else:
            self.contents.append(Paragraph(text, style))
        self._spacer()

    def createtable(self, ident, header, style, validation=None):
        # Layout is [headings, ....]
        self.table_data = []
        self.table_style = style
        self.table_ident = ident
        # Validation is list of items indicating max length of item in each column.
        # None indicates no limit for column
        if validation is not None:
            # Assume validation for all columns provided
            self.table_validation = validation
        else:
            # No validation specified
            self.table_validation = [None] * len(header)
        if header:
            self.addrow(ident, header)

    def validatedata(self, data):
        i = 0
        newdata = []
        for d in data:
            if self.table_validation[i] is not None:
                # Column size validation
                if len(d) > self.table_validation[i]:
                    if d not in self.note_data:
                        self.note_data.append(d)
                    newdata.append("Note " + str(self.note_data.index(d) + 1))
                else:
                    newdata.append(d)
            else:
                newdata.append(d)
            i += 1
        return newdata

    def addrow(self, ident, data, style=None):
        # Add row to table
        if self.table_ident == ident:
            self.table_data.append(self.validatedata(data))
            if style != None:
                for s in style:
                    # Only take first 4 parameters in each style setting
                    self.table_style.add(s[0], s[1], s[2], s[3])

    def showtable(self, ident, widths=None):
        if self.table_ident == ident:
            self._spacer()
            tbl = Table(self.table_data, colWidths=widths, repeatRows=1)
            tbl.setStyle(self.table_style)
            self.contents.append(tbl)
            self.table_ident = None
            # Optional notes if data in columns truncated
            if len(self.note_data) > 0:
                notes = ["<br/><u>Notes</u>"]
                i = 1
                for d in self.note_data:
                    notes.append(str(i) + ". " + d)
                    i += 1
                self.paragraph("<br/>".join(notes))
                self.note_data = []
            self._spacer()

    def pagebreak(self):
        self.contents.append(PageBreak())

    def _logo(self, text):
        d = Drawing(400, 400)
        d.add(Rect(50, 50, 300, 300, fillColor=colors.green))
        d.add(
            String(
                100,
                200,
                text,
                fontName="Helvetica-Bold",
                fontSize=96,
                fillColor=colors.black,
            )
        )
        d.add(
            String(
                75,
                100,
                "Produced by cve-bin-tool",
                fontName="Helvetica",
                fontSize=24,
                fillColor=colors.black,
            )
        )
        return d

    def front_page(self, pagetitle):
        # Front page
        logo = self._logo("CVE")
        now = datetime.now()
        date_time = now.strftime("%d %B %Y at %H:%M:%S")
        front_page = [
            [logo],
            [Paragraph(pagetitle, self.h1)],
            [Paragraph("Report generated on " + date_time, self.h3)],
        ]
        tbl = Table(front_page, colWidths=10 * cm)
        tbl.setStyle(self.frontPageStyle)
        self.contents.append(tbl)
        self.pagebreak()

    def tableofcontents(self):
        if self.toc_included:
            self.paragraph("Table of Contents")
            self._spacer()
            self.contents.append(self.toc)
            self.pagebreak()

    def pageLayout(self, canvas, doc):
        pageinfo = "CVE Report"
        canvas.saveState()
        canvas.setFont("Helvetica", 10)
        canvas.drawString(10 * cm, 2 * cm, "Page %d" % doc.page)
        canvas.drawString(16 * cm, 28 * cm, "%s" % pageinfo)
        canvas.restoreState()

    def publish(self, filename, includeTOC=True):
        if includeTOC and self.toc_included:
            doc = PDFDocTemplate(filename)
            doc.multiBuild(self.contents, onLaterPages=self.pageLayout)
        else:
            doc = SimpleDocTemplate(filename)
            doc.build(self.contents, onLaterPages=self.pageLayout)
