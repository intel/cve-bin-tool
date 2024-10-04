"""An extension to capture amsmath latex environments."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Callable, Sequence

from markdown_it import MarkdownIt
from markdown_it.common.utils import escapeHtml
from markdown_it.rules_block import StateBlock

from mdit_py_plugins.utils import is_code_block

if TYPE_CHECKING:
    from markdown_it.renderer import RendererProtocol
    from markdown_it.token import Token
    from markdown_it.utils import EnvType, OptionsDict

# Taken from amsmath version 2.1
# http://anorien.csc.warwick.ac.uk/mirrors/CTAN/macros/latex/required/amsmath/amsldoc.pdf
ENVIRONMENTS = [
    # 3.2 single equation with an automatically gen-erated number
    "equation",
    # 3.3 variation equation, used for equations that dont fit on a single line
    "multline",
    # 3.5 a group of consecutive equations when there is no alignment desired among them
    "gather",
    # 3.6 Used for two or more equations when vertical alignment is desired
    "align",
    # allows the horizontal space between equationsto be explicitly specified.
    "alignat",
    # stretches the space betweenthe equation columns to the maximum possible width
    "flalign",
    # 4.1 The pmatrix, bmatrix, Bmatrix, vmatrix and Vmatrix have (respectively)
    # (),[],{},||,and ‖‖ delimiters built in.
    "matrix",
    "pmatrix",
    "bmatrix",
    "Bmatrix",
    "vmatrix",
    "Vmatrix",
    # eqnarray is another math environment, it is not part of amsmath,
    # and note that it is better to use align or equation+split instead
    "eqnarray",
]
# other "non-top-level" environments:

# 3.4 the split environment is for single equations that are too long to fit on one line
# and hence must be split into multiple lines,
# it is intended for use only inside some other displayed equation structure,
# usually an equation, align, or gather environment

# 3.7 variants gathered, aligned,and alignedat are provided
# whose total width is the actual width of the contents;
# thus they can be used as a component in a containing expression

RE_OPEN = re.compile(r"\\begin\{(" + "|".join(ENVIRONMENTS) + r")([\*]?)\}")


def amsmath_plugin(
    md: MarkdownIt, *, renderer: Callable[[str], str] | None = None
) -> None:
    """Parses TeX math equations, without any surrounding delimiters,
    only for top-level `amsmath <https://ctan.org/pkg/amsmath>`__ environments:

    .. code-block:: latex

        \\begin{gather*}
        a_1=b_1+c_1\\\\
        a_2=b_2+c_2-d_2+e_2
        \\end{gather*}

    :param renderer: Function to render content, by default escapes HTML

    """
    md.block.ruler.before(
        "blockquote",
        "amsmath",
        amsmath_block,
        {"alt": ["paragraph", "reference", "blockquote", "list", "footnote_def"]},
    )

    _renderer = (lambda content: escapeHtml(content)) if renderer is None else renderer

    def render_amsmath_block(
        self: RendererProtocol,
        tokens: Sequence[Token],
        idx: int,
        options: OptionsDict,
        env: EnvType,
    ) -> str:
        content = _renderer(str(tokens[idx].content))
        return f'<div class="math amsmath">\n{content}\n</div>\n'

    md.add_render_rule("amsmath", render_amsmath_block)


def match_environment(string: str) -> None | tuple[str, str, int]:
    match_open = RE_OPEN.match(string)
    if not match_open:
        return None
    environment = match_open.group(1)
    numbered = match_open.group(2)
    match_close = re.search(
        r"\\end\{" + environment + numbered.replace("*", r"\*") + "\\}", string
    )
    if not match_close:
        return None
    return (environment, numbered, match_close.end())


def amsmath_block(
    state: StateBlock, startLine: int, endLine: int, silent: bool
) -> bool:
    if is_code_block(state, startLine):
        return False

    begin = state.bMarks[startLine] + state.tShift[startLine]

    outcome = match_environment(state.src[begin:])
    if not outcome:
        return False
    environment, numbered, endpos = outcome
    endpos += begin

    line = startLine
    while line < endLine:
        if endpos >= state.bMarks[line] and endpos <= state.eMarks[line]:
            # line for end of block math found ...
            state.line = line + 1
            break
        line += 1

    if not silent:
        token = state.push("amsmath", "math", 0)
        token.block = True
        token.content = state.src[begin:endpos]
        token.meta = {"environment": environment, "numbered": numbered}
        token.map = [startLine, line]

    return True
