# XRef — build-time syntax highlighting for the /docs/ pages
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Tokenize fenced code into `<span class="tok-…">` runs. Every byte of the input is kept and
HTML-escaped, so copying the rendered block yields the original text; only these classes are
emitted: tok-prompt, tok-cmd, tok-flag, tok-str, tok-num, tok-key, tok-com, tok-kw, tok-type,
tok-addr, tok-op, tok-reg, tok-lit."""

import html
import re

C_KEYWORDS = r"if|else|while|do|for|return|switch|case|break|continue|goto|default|sizeof"
C_TYPES = r"void|u8|u16|u32|u64|u128|i8|i16|i32|i64|i128|usize|isize|unk8|unk16|unk32|unk64|bool|char|f32|f64"
REGS = (r"r[a-d]x|r[sd]i|r[sb]p|r(?:[89]|1[0-5])[dwb]?|e[a-d]x|e[sd]i|e[sb]p|[a-d][lh]|[sd]il|[sb]pl|"
        r"xmm\d+|ymm\d+|rip")

RULES = {
    "console": [
        ("prompt", r"^\$ "),
        ("cmd", r"(?<=^\$ )(?:sudo )?xref\b"),
        ("str", r"\"[^\"\n]*\"|'[^'\n]*'"),
        ("flag", r"(?<=\s)--?[A-Za-z][\w-]*"),
        ("num", r"\b0x[0-9a-fA-F]+\b"),
    ],
    "json": [
        ("key", r"\"(?:[^\"\\\n]|\\.)*\"(?=\s*:)"),
        ("str", r"\"(?:[^\"\\\n]|\\.)*\""),
        ("num", r"-?\b\d+(?:\.\d+)?\b"),
        ("lit", r"\b(?:true|false|null)\b"),
    ],
    "c": [
        ("com", r"/\*.*?\*/|//[^\n]*"),
        ("str", r"\"(?:[^\"\\\n]|\\.)*\""),
        ("kw", rf"\b(?:{C_KEYWORDS})\b"),
        ("type", rf"\b(?:{C_TYPES})\b"),
        ("num", r"\b0x[0-9a-fA-F]+\b|\b\d+\b"),
    ],
    "asm": [
        ("com", r";[^\n]*"),
        ("addr", r"^0x[0-9a-fA-F]+"),
        ("op", r"(?<=\s\s)[a-z][a-z0-9]*(?= |$)"),
        ("reg", rf"\b(?:{REGS})\b"),
        ("num", r"\b0x[0-9a-fA-F]+\b|\b\d+\b"),
    ],
}
ALIASES = {"sh": "console", "bash": "console", "shell": "console"}


def highlight(code, lang):
    """HTML for `code`; languages without rules are escaped only."""
    rules = RULES.get(ALIASES.get(lang, lang))
    if not rules:
        return html.escape(code, quote=False)
    pattern = re.compile("|".join(f"(?P<{name}_{i}>{rx})" for i, (name, rx) in enumerate(rules)), re.M | re.S)
    out, pos = [], 0
    for m in pattern.finditer(code):
        if m.start() < pos or m.end() == m.start():
            continue
        out.append(html.escape(code[pos:m.start()], quote=False))
        kind = m.lastgroup.rsplit("_", 1)[0]
        out.append(f'<span class="tok-{kind}">{html.escape(m.group(0), quote=False)}</span>')
        pos = m.end()
    out.append(html.escape(code[pos:], quote=False))
    return "".join(out)
