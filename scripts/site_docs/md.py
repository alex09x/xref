# XRef — the Markdown subset used by docs/*.md, rendered to HTML for xrefcode.com
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Headings, paragraphs, nested lists, fenced code, pipe tables, block quotes / GitHub alerts,
inline code, links, bold and italics. No raw HTML passes through (the site has a strict CSP)."""

import html
import posixpath
import re

from highlight import highlight

REPO = "https://github.com/alex09x/xref/blob/main/"
INLINE = re.compile(r"`([^`]+)`|\[([^\]]+)\]\(((?:[^()\s]|\([^()\s]*\))+)\)|\*\*(.+?)\*\*|(?<![\w*])\*([^*\s][^*]*?)\*(?![\w*])|<(https?://[^>]+)>")
FENCE = re.compile(r"^(\s*)```")
LIST = re.compile(r"^(\s*)([-*]|\d+\.)\s+(.*)$")
ALERT = re.compile(r"^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$")


def anchor(text):
    """GitHub-style heading anchor."""
    text = re.sub(r"`|\*\*|\*|\[([^\]]+)\]\([^)]*\)", lambda m: m.group(1) or "", text)
    return re.sub(r"[^\w\- ]", "", text.strip().lower()).replace(" ", "-")


SITE_PAGES = set()  # guide names rendered under /docs/, filled by build.py


SAFE_SCHEMES = {"http", "https", "mailto"}


def link_target(target, page):
    """Rewrite a Markdown link for the site: sibling guides become /docs/ pages, repository files GitHub URLs.

    Returns None for any other URL scheme (javascript:, data:, ...); the caller renders the label as text."""
    scheme = re.match(r"^\s*([A-Za-z][A-Za-z0-9+.\-]*):", target)
    if scheme:
        return target if scheme.group(1).lower() in SAFE_SCHEMES else None
    if target.startswith("#"):
        return target
    path, _, frag = target.partition("#")
    frag = f"#{frag}" if frag else ""
    norm = posixpath.normpath(posixpath.join("docs", posixpath.dirname(page), path))
    if norm.startswith("docs/") and norm.endswith(".md"):
        name = norm[5:-3]
        if name == "live-walkthrough":
            return "/live-walkthrough" + frag
        if name in SITE_PAGES:
            return f"/docs/{name}" + frag
    return REPO + norm + frag


def inline(text, page):
    out, pos = [], 0
    for m in INLINE.finditer(text):
        out.append(html.escape(text[pos:m.start()], quote=False))
        code, label, target, bold, em, auto = m.groups()
        if code is not None:
            out.append(f"<code>{html.escape(code, quote=False)}</code>")
        elif label is not None:
            href = link_target(target, page)
            out.append(inline(label, page) if href is None else f'<a href="{html.escape(href)}">{inline(label, page)}</a>')
        elif bold is not None:
            out.append(f"<strong>{inline(bold, page)}</strong>")
        elif em is not None:
            out.append(f"<em>{inline(em, page)}</em>")
        else:
            out.append(f'<a href="{html.escape(auto)}">{html.escape(auto, quote=False)}</a>')
        pos = m.end()
    out.append(html.escape(text[pos:], quote=False))
    return "".join(out)


BLOCK_LABELS = {"console": "Command", "sh": "Command", "bash": "Command", "shell": "Command", "stderr": "stderr",
                "output": "Output", "json": "JSON", "c": "C", "asm": "Assembly", "rust": "Rust", "toml": "TOML"}


def code_block(code, info):
    """A labelled, highlighted code panel. `info` is the fence info string, e.g. `console` or `json output`."""
    words = info.split()
    lang = words[0] if words else ""
    kind = "output" if "output" in words[1:] else "stderr" if lang == "stderr" else "command" if lang in (
        "console", "sh", "bash", "shell") else "code"
    label = "Output" if kind == "output" else BLOCK_LABELS.get(lang, "")
    head = f'<div class="doc-block-label">{html.escape(label)}</div>' if label else ""
    body = highlight(code, lang) if lang != "text" else html.escape(code, quote=False)
    return (f'<div class="doc-block doc-block-{kind}">{head}'
            f'<pre class="code-view doc-code" data-lang="{html.escape(lang)}">{body}</pre></div>')


def title_and_summary(source):
    lines = source.splitlines()
    title = next((l[2:].strip() for l in lines if l.startswith("# ")), "XRef")
    title = re.sub(r"`", "", title)
    para, started = [], False
    for line in lines:
        if line.startswith("# "):
            started = True
            continue
        if not started or line.startswith(("<!--", ">")):
            continue
        if not line.strip():
            if para:
                break
            continue
        if line.startswith(("#", "```", "|", "-", "*")) or re.match(r"\d+\.", line):
            if para:
                break
            continue
        para.append(line.strip())
    summary = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", " ".join(para)).replace("`", "")
    return title, summary[:300]


OPTION_HEADER = ["Option", "Description", "Default"]


def table(rows, page):
    split = lambda r: [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", r.strip().strip("|"))]  # noqa: E731
    cells = [split(r) for r in rows]
    head, body = cells[0], cells[2:]
    if head == OPTION_HEADER:
        return option_cards(body, page)
    out = ['<div class="table-scroll"><table class="doc-table"><thead><tr>']
    out += [f"<th>{inline(c, page)}</th>" for c in head] + ["</tr></thead><tbody>"]
    for r in body:
        out += ["<tr>"] + [f"<td>{inline(c, page)}</td>" for c in r] + ["</tr>"]
    return "".join(out + ["</tbody></table></div>"])


def list_block(items, page):
    """items: list of (indent, ordered, text-lines) parsed in order; builds nested lists by indent."""
    out, stack = [], []
    for indent, ordered, text in items:
        while stack and indent < stack[-1][0]:
            out.append(f"</li></{stack.pop()[1]}>")
        if stack and indent == stack[-1][0]:
            out.append("</li>")
        if not stack or indent > stack[-1][0]:
            tag = "ol" if ordered else "ul"
            stack.append((indent, tag))
            out.append(f"<{tag}>")
        out.append(f"<li>{inline(' '.join(text), page)}")
    while stack:
        out.append(f"</li></{stack.pop()[1]}>")
    return "".join(out)


def option_cards(rows, page):
    """A command's `| Option | Description | Default |` table as a grid of option cards."""
    out = ['<div class="opt-cards">']
    for flag, desc, default, *_ in [r + ["", "", ""] for r in rows]:
        meta = f'<div class="opt-meta">default {inline(default, page)}</div>' if default else ""
        out.append(f'<div class="opt-card"><div class="opt-flag">{inline(flag, page)}</div>'
                   f'<div class="opt-text">{inline(desc, page)}</div>{meta}</div>')
    return "".join(out + ["</div>"])


SESSION_PARTS = ('<div class="doc-block doc-block-output', '<div class="doc-block doc-block-stderr')
SESSION_NOTES = re.compile(r"^<p>(?:<em>(?:Output cut here|First \d+ lines omitted)|Exit status \d+\.)")


def group_sessions(blocks):
    """Merge each command block with the output, stderr and cut/exit notes that follow it into one session."""
    out, i = [], 0
    while i < len(blocks):
        if not blocks[i].startswith('<div class="doc-block doc-block-command'):
            out.append(blocks[i])
            i += 1
            continue
        parts = [blocks[i]]
        i += 1
        while i < len(blocks) and (blocks[i].startswith(SESSION_PARTS) or SESSION_NOTES.match(blocks[i])):
            part = blocks[i]
            parts.append(f'<div class="sess-note">{part[3:-4]}</div>' if part.startswith("<p>") else part)
            i += 1
        out.append(f'<div class="doc-session">{"".join(parts)}</div>' if len(parts) > 1 else parts[0])
    return out


def render(source, page):
    """Return (body_html, toc) where toc lists (level, anchor, title) for ## and ### headings."""
    lines = source.splitlines()
    out, toc, i = [], [], 0
    seen = {}
    skipped_title = False
    while i < len(lines):
        line = lines[i]
        if line.startswith("<!--"):
            while "-->" not in lines[i]:
                i += 1
            i += 1
            continue
        fence = FENCE.match(line)
        if fence:
            indent = len(fence.group(1))
            lang = line.strip()[3:].strip()
            i += 1
            code = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i][indent:] if lines[i][:indent].strip() == "" else lines[i])
                i += 1
            i += 1
            out.append(code_block(chr(10).join(code), lang))
            continue
        h = re.match(r"^(#{1,4})\s+(.*)$", line)
        if h:
            level, text = len(h.group(1)), h.group(2).strip()
            i += 1
            if level == 1 and not skipped_title:
                skipped_title = True
                continue
            a = anchor(text)
            seen[a] = seen.get(a, -1) + 1
            if seen[a]:
                a = f"{a}-{seen[a]}"
            if level in (2, 3):
                toc.append((level, a, re.sub(r"`", "", text)))
            out.append(f'<h{level} id="{a}">{inline(text, page)}</h{level}>')
            continue
        if line.startswith("|") and i + 1 < len(lines) and re.match(r"^\|?\s*:?-+:?\s*\|", lines[i + 1]):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(lines[i])
                i += 1
            out.append(table(rows, page))
            continue
        if line.startswith(">"):
            quote = []
            while i < len(lines) and lines[i].startswith(">"):
                quote.append(lines[i][1:].strip())
                i += 1
            kind = ALERT.match(quote[0]) if quote else None
            if kind:
                quote = quote[1:]
            cls = f"doc-alert doc-alert-{kind.group(1).lower()}" if kind else "doc-quote"
            label = f'<strong class="doc-alert-label">{kind.group(1).title()}</strong> ' if kind else ""
            out.append(f'<div class="{cls}"><p>{label}{inline(" ".join(q for q in quote if q), page)}</p></div>')
            continue
        if LIST.match(line):
            items = []
            while i < len(lines):
                m = LIST.match(lines[i])
                if m:
                    items.append((len(m.group(1)), m.group(2)[-1] == ".", [m.group(3).strip()]))
                    i += 1
                elif lines[i].strip() and lines[i].startswith(" ") and items and not FENCE.match(lines[i]):
                    items[-1][2].append(lines[i].strip())
                    i += 1
                elif not lines[i].strip() and i + 1 < len(lines) and (LIST.match(lines[i + 1]) or lines[i + 1].startswith("  ")) \
                        and not FENCE.match(lines[i + 1]):
                    i += 1
                else:
                    break
            out.append(list_block(items, page))
            continue
        if not line.strip():
            i += 1
            continue
        para = [line.strip()]  # always consume the current line, so an unmatched block start cannot loop
        i += 1
        while i < len(lines) and lines[i].strip() and not (
            FENCE.match(lines[i]) or re.match(r"^#{1,4}\s", lines[i]) or lines[i].startswith((">", "|", "<!--"))
            or LIST.match(lines[i])
        ):
            para.append(lines[i].strip())
            i += 1
        out.append(f"<p>{inline(' '.join(para), page)}</p>")
    return "\n".join(group_sessions(out)), toc
