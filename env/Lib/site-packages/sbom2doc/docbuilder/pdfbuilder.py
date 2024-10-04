# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from reportlab import rl_config
from reportlab.lib import colors
from reportlab.lib.styles import ListStyle
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
from reportlab.platypus.tables import Table

from sbom2doc.docbuilder.docbuilder import DocBuilder


class PDFDocTemplate(SimpleDocTemplate):
    def __init__(self, filename, **kw):
        self.allowSplitting = 0
        BaseDocTemplate.__init__(self, filename, **kw)
        template = PageTemplate(
            "normal", [Frame(2.5 * cm, 2.5 * cm, 15 * cm, 25 * cm, id="F1")]
        )
        self.addPageTemplates(template)


class ConditionalSpacer(Spacer):
    def wrap(self, availWidth, availHeight):
        height = min(self.height, availHeight - 1e-8)
        return (availWidth, height)


class PDFBuilder(DocBuilder):

    document_font = "Helvetica"
    document_font_bold = document_font + "-Bold"

    h1 = PS(name="Heading1", fontSize=16, fontName=document_font_bold, leading=18)

    body = PS(name="body", fontSize=12, fontName=document_font, leading=18)

    black = colors.black

    spacer = ConditionalSpacer(0.25 * cm, 0.25 * cm)

    tblStyle = TableStyle(
        [
            ("INNERGRID", (0, 0), (-1, -1), 0.25, black),
            ("BOX", (0, 0), (-1, -1), 0.25, black),
            ("FONT", (0, 0), (-1, -1), document_font, 12),
            ("FONT", (0, 0), (-1, 0), document_font_bold),
        ]
    )

    list = ListStyle(
        name="list",
        fontSize=10,
        fontName=document_font,
        leading=12,
        textColor=black,
        textTransform=None,
        firstLineIndent=12,
        wordWrap=True,
        uriWasteReduce=None,
        embeddedHyphenation=True,
        spaceShrinkage=True,
        splitLongWords=True,
        justifyBreaks=True,
        justifyLastLine=False,
        endDots=False,
        backColor=colors.white,
        alignment=False,
    )

    def __init__(self):
        self.contents = []
        self.headingnumber = [0, 0, 0, 0]
        self.table_data = []
        self.note_data = []
        self.table_validation = None
        # Set default configuration parameters
        rl_config.trustedHosts = ["localhost", "127.0.0.1"]
        rl_config.trustedSchemes = ["http", "https"]

    def _spacer(self):
        self.contents.append(self.spacer)

    def heading(self, level, title, number=True):
        self._spacer()
        if level == 1:
            self.headingnumber[level] += 1
            self.headingnumber[level + 1] = 0
        elif level == 2:
            self.headingnumber[level] += 1
        elif level > 2:
            print("Ooops.... Level", level)
        if number:
            if level == 1:
                self.contents.append(
                    Paragraph(str(self.headingnumber[level]) + ". " + title, self.h1)
                )
            else:
                self.contents.append(
                    Paragraph(
                        str(self.headingnumber[level - 1])
                        + "."
                        + str(self.headingnumber[level])
                        + ". "
                        + title,
                        self.h1,
                    )
                )
        else:
            self.contents.append(Paragraph(title, self.h1))
        self._spacer()

    def paragraph(self, text):
        # Line breaks preserved if required
        text_elements = text.splitlines()
        for t in text_elements:
            self.contents.append(Paragraph(t, self.body))
            self._spacer()

    def _notes_paragraph(self, text):
        self.contents.append(Paragraph(text, self.list))
        self._spacer()

    def createtable(self, header, validate=None):
        # Layout is [headings, ....]
        self.table_data = []
        self.table_style = self.tblStyle
        if validate is None:
            self.table_validation = [None] * len(header)
        else:
            self.table_validation = validate
        if header:
            self.addrow(header)

    def _validatedata(self, data):
        i = 0
        newdata = []
        for d in data:
            if self.table_validation[i] is not None:
                # Column size validation
                if d is None:
                    newdata.append("")
                elif len(d) > self.table_validation[i]:
                    if d not in self.note_data:
                        self.note_data.append(d)
                    newdata.append("Note " + str(self.note_data.index(d) + 1))
                else:
                    newdata.append(d)
            else:
                newdata.append(d)
            i += 1
        return newdata

    def addrow(self, data):
        # Add row to table
        self.table_data.append(self._validatedata(data))

    def showtable(self, widths=None):
        colwidths = [w * cm for w in widths]
        self._spacer()
        tbl = Table(self.table_data, colWidths=colwidths, repeatRows=1)
        tbl.setStyle(self.table_style)
        self.contents.append(tbl)
        self.table_ident = None
        # Optional notes if data in columns truncated
        if len(self.note_data) > 0:
            notes = ["<br/><u>Notes</u><br/><ul>"]
            i = 1
            for d in self.note_data:
                notes.append(f"<li>{str(i):>4} . {d}</li>")
                i += 1
            self._notes_paragraph("</ul><br/>".join(notes))
            self.note_data = []
        self._spacer()

    def pagebreak(self):
        self.contents.append(PageBreak())

    def _pageLayout(self, canvas, doc, pageinfo="SBOM Report"):
        canvas.saveState()
        canvas.setFont(self.document_font, 10)
        canvas.drawString(10 * cm, 2 * cm, "Page %d" % doc.page)
        canvas.drawString(16 * cm, 28 * cm, "%s" % pageinfo)
        canvas.restoreState()

    def publish(self, filename):
        doc = SimpleDocTemplate(filename)
        doc.build(self.contents, onLaterPages=self._pageLayout)
