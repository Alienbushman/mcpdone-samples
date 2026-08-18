"""jsparse — a masking lexer for TypeScript / JavaScript source.

mcp-audit is stdlib-only, so there is no TS parser available and there
never will be one (a `pip install mcpdone-audit` must not pull node,
tree-sitter, or a wasm blob). This module is the substitute: it produces
a *masked* copy of the source, byte-for-byte the same length as the
original, in which comments and string-literal contents have been
replaced by spaces. Every offset in the masked text addresses the same
character in the original, so a match found in the mask can be sliced out
of the real source for reporting.

What the mask preserves, and why each one matters:

  - `//` and `/* */` comments are blanked, but a `//` *inside* a string
    ("https://x") is not — a naive comment stripper truncates the rest of
    the line and desynchronises every subsequent bracket.
  - `'...'` and `"..."` contents are blanked. These cannot span a raw
    newline in JS, so a scan that reaches a newline before the closing
    quote is treated as "this was not a string after all" — that single
    rule contains almost all of the damage a mis-lexed regex can do.
  - Template literals blank their text chunks but KEEP `${` ... `}` and
    everything between, recursively masked. Interpolated expressions are
    live code: ``exec(`git checkout ${branch}`)`` is precisely the shape
    ts_command_injection exists to find, and blanking the hole would make
    the check blind to its own motivating case.
  - Regex literals are blanked, using a previous-significant-token
    heuristic to tell `/re/` from division. This is the one genuinely
    undecidable case in JS lexing. We do not pretend to solve it; we
    bound it. See `Source.ok`.

Newline characters are never blanked, in any construct. Blanking them
would not break offsets (line numbers come from the original text) but it
would destroy the line structure of the mask, which line-oriented
matching depends on.

`Source.ok` is False when the lexer ran off the end of the file inside a
string, template, comment, or bracket group. Every check MUST return []
for a file whose `Source.ok` is False. A degraded lex must never emit a
finding — a false positive from a mis-lexed file is exactly the class of
defect that produced the v0.3 command_injection retraction.

Known lexing limits, recorded rather than hidden:

  - `if (x) /re/.test(y)` is read as division, because the previous
    significant character is `)`. The regex body stays live. The
    newline-bounded string rule caps the damage at one line, and any
    resulting bracket imbalance sets `ok=False`.
  - JSX text in `.tsx` files is ordinary code to this lexer. An
    apostrophe in JSX prose opens a phantom string that dies at the end
    of the line. A closing tag `</Foo>` is recognised by a narrow
    heuristic so it does not start a regex.
  - Angle-bracket generics are tracked only well enough to stop
    `Record<string, any>` splitting an argument list in two; a genuine
    `a < b, c > d` in an argument list would be mis-split.

Nothing in this module knows what MCP is. MCP tool-registration shapes
live in `mcp_audit.tstools`.
"""
from __future__ import annotations

import bisect
import os
import re
from collections.abc import Collection, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------
# File discovery constants (design §2). Exported so the check modules can
# reuse them instead of re-typing the set.
#
# NOTE FOR CHECK IMPLEMENTERS: this skip set contains "test", "tests",
# "fixtures", "examples". `iter_source_files` prunes them during an os.walk
# that STARTS AT `root`, so components ABOVE root are never examined — a
# check invoked with root=tests/fixtures/ts_noise_common still sees its
# files. If you copy this set into a module-level `_should_skip(path)` that
# tests `path.parts`, every one of your own fixtures becomes invisible and
# your tests will pass vacuously. Test `path.relative_to(root).parts`, or
# keep your local copy limited to the six Python checks' house set.
# --------------------------------------------------------------------------
TS_EXTENSIONS: frozenset[str] = frozenset(
    {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
)

TS_SKIP_DIRS: frozenset[str] = frozenset({
    # house set (identical to the other six checks)
    ".venv", "venv", "env", "node_modules", ".git", "site-packages",
    ".tox", ".nox", "build", "dist", "__pycache__",
    # TS/JS additions: compiled output, caches, vendored trees
    "out", "coverage", ".next", ".nuxt", ".svelte-kit", ".turbo",
    ".vercel", ".cache", "bower_components", "vendor",
    # test / example trees
    "test", "tests", "__tests__", "__mocks__", "e2e", "fixtures",
    "examples", "example", "demo", "benchmark", "benchmarks", "evals",
})

# Marker returned as `CallSite.receiver` / `.root` when the callee is a
# member of something that is not a plain identifier chain — `foo().rm(x)`,
# `arr[0].exec(y)`. Non-empty (so "is this a member call?" gates pass) but
# it can never match an import binding, so import-gated sink resolution
# correctly refuses to treat it as a sink.
UNKNOWN_RECEIVER = "?"

_OPEN = "([{"
_CLOSE = ")]}"
_PAIR = {")": "(", "]": "[", "}": "{"}
_WS = " \t\r\n\v\f\u00a0\ufeff"

_IDENT_FULL_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")

# Keywords after which a `/` begins a regex literal, not a division.
_REGEX_KEYWORDS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await",
})
# Punctuation after which a `/` begins a regex literal.
_REGEX_PUNCT = frozenset("(,=:[!&|?{};+-*%~^<>")

# Bare callee names that are language syntax, never a call we care about.
_CALL_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "return", "typeof", "await",
    "super", "function", "class", "new", "delete", "void", "throw", "case",
    "do", "else", "yield", "in", "of", "instanceof", "import", "export",
    "with", "const", "let", "var",
})

# Characters that, at the start of the next line, continue the previous
# expression rather than beginning a new statement (ASI approximation).
_CONTINUATION_CHARS = frozenset(".?:,)]}+-*/%&|^=<>")
_CONTINUATION_WORDS = ("in", "of", "instanceof", "as", "satisfies")


# ==========================================================================
# dataclasses
# ==========================================================================
@dataclass(frozen=True, order=True)
class Span:
    """Half-open byte range [start, end) into a Source's text.

    Note that `__len__` is defined, so an *empty* Span is falsy. Use
    `.is_empty()` in conditionals rather than truthiness when the
    distinction between "no span" (None) and "empty span" matters.
    """

    start: int
    end: int

    def __len__(self) -> int:
        return max(0, self.end - self.start)

    def __contains__(self, offset: int) -> bool:
        return self.start <= offset < self.end

    def is_empty(self) -> bool:
        return self.end <= self.start


@dataclass(frozen=True)
class Source:
    """A lexed source file. `text` is verbatim; `masked` is the same length
    with comments / string contents blanked. `ok` False => unusable."""

    path: Path
    text: str
    masked: str
    ok: bool
    line_starts: tuple[int, ...]

    def line_of(self, offset: int) -> int:
        """1-based line number for a byte offset. Clamps to [1, nlines]."""
        if offset < 0:
            return 1
        n = bisect.bisect_right(self.line_starts, offset)
        return max(1, min(n if n else 1, len(self.line_starts)))

    def raw(self, span: Span) -> str:
        """Original text of a span — use for prose, tool names, quoting."""
        return self.text[max(0, span.start):max(0, span.end)]

    def code(self, span: Span) -> str:
        """Masked text of a span — use for ALL pattern matching."""
        return self.masked[max(0, span.start):max(0, span.end)]

    def trimmed(self, span: Span) -> Span:
        """Span with leading/trailing whitespace removed (masked-aware)."""
        m = self.masked
        s = max(0, min(span.start, len(m)))
        e = max(s, min(span.end, len(m)))
        while s < e and m[s] in _WS:
            s += 1
        while e > s and m[e - 1] in _WS:
            e -= 1
        return Span(s, e)


@dataclass(frozen=True)
class CallSite:
    callee: str        # dotted text as written: "server.registerTool", "fs.promises.rm"
    method: str        # last segment: "registerTool", "rm"
    receiver: str      # everything before the last dot; "" when a bare name
    root: str          # leftmost identifier of the callee chain; == method when bare
    is_new: bool       # preceded by the `new` keyword
    name_span: Span    # the callee text
    args_span: Span    # INSIDE the parens, exclusive of both parens
    call_span: Span    # `new`?/callee through the closing paren, inclusive
    args: tuple[Span, ...]   # top-level comma-split argument spans, trailing empty INCLUDED
    line: int          # 1-based, at name_span.start


@dataclass(frozen=True)
class Param:
    """One *binding* produced by a parameter. A destructuring pattern
    produces several Params that all share `index`."""

    name: str          # the local binding name ({id: orgId} -> "orgId")
    source_name: str   # the property name ({id: orgId} -> "id"); == name when plain
    index: int         # positional index of the parameter this came from
    is_rest: bool      # `...params`
    is_destructured: bool
    span: Span
    type_text: str     # "" when unannotated; e.g. "any", "z.infer<typeof S>"


@dataclass(frozen=True)
class FunctionBody:
    kind: str          # "arrow" | "function" | "method"
    is_async: bool
    params: tuple[Param, ...]
    positional_count: int      # number of declared parameters, not bindings
    params_ok: bool            # False => a pattern we could not parse; callers MUST suppress
    params_span: Span | None
    body_span: Span            # braced body: INSIDE the braces. concise arrow: the expression.
    body_is_expression: bool
    span: Span                 # the whole function expression
    line: int

    def param_at(self, index: int) -> tuple[Param, ...]:
        """All bindings produced by positional parameter `index`."""
        return tuple(p for p in self.params if p.index == index)


@dataclass(frozen=True)
class ObjectEntry:
    key: str           # "" for computed keys and spreads
    key_span: Span
    value_span: Span   # empty span for shorthand
    is_shorthand: bool
    is_method: bool    # `async handler(a, b) { ... }`
    is_spread: bool
    line: int


@dataclass(frozen=True)
class ObjectLiteral:
    span: Span         # INCLUDING the braces
    entries: tuple[ObjectEntry, ...]
    has_spread: bool
    ok: bool           # False => malformed / gave up; callers MUST suppress

    def get(self, key: str) -> ObjectEntry | None:
        for e in self.entries:
            if e.key == key:
                return e
        return None


@dataclass(frozen=True)
class ImportRecord:
    module: str        # "node:child_process", "fs/promises", "@modelcontextprotocol/sdk/server/mcp.js"
    local: str         # local binding name
    imported: str      # original export name; "*" namespace, "default" default
    is_type_only: bool  # `import type { X }` — proves MCP context, is not a runtime binding
    line: int


@dataclass(frozen=True)
class Binding:
    name: str
    kind: str          # "const" | "let" | "var" | "function" | "class"
    value_span: Span   # the initializer; empty span when there is none
    line: int


# ==========================================================================
# lexer
# ==========================================================================
def _blank(buf: list[str], text: str, start: int, end: int) -> None:
    """Overwrite [start, end) with spaces, preserving newlines."""
    n = len(buf)
    for k in range(max(0, start), min(end, n)):
        if text[k] != "\n":
            buf[k] = " "


def _prev_significant(buf: list[str], i: int) -> int:
    """Index of the last non-whitespace char in buf before i, or -1."""
    k = i - 1
    while k >= 0 and buf[k] in _WS:
        k -= 1
    return k


def _word_ending_at(buf: list[str], k: int) -> str:
    """The identifier that ends at index k (inclusive), or ""."""
    j = k
    while j >= 0 and (buf[j].isalnum() or buf[j] in "_$"):
        j -= 1
    word = "".join(buf[j + 1:k + 1])
    return word if _IDENT_FULL_RE.match(word) else ""


def _in_regex_position(buf: list[str], i: int) -> bool:
    """Decide whether the `/` at index i opens a regex literal (design §1.5)."""
    k = _prev_significant(buf, i)
    if k < 0:
        return True
    p = buf[k]
    if p in _REGEX_PUNCT:
        return True
    if p.isalnum() or p in "_$":
        return _word_ending_at(buf, k) in _REGEX_KEYWORDS
    return False


def _looks_like_jsx_close(text: str, i: int) -> bool:
    """True when the `/` at i is the slash of a JSX closing tag `</Foo>`.

    Only consulted when the previous significant character is `<`, which is
    otherwise a regex position. `a < /re/.test(b)` is not real code; JSX
    closing tags are, in every .tsx file in the corpus.
    """
    j = i + 1
    n = len(text)
    while j < n and (text[j].isalnum() or text[j] in "_$.-:"):
        j += 1
    if j == i + 1:
        return False
    while j < n and text[j] in " \t":
        j += 1
    return j < n and text[j] == ">"


def _scan_regex(text: str, i: int) -> tuple[int, int] | None:
    """Scan a regex literal starting at the `/` at i.

    Returns (body_end, end) where body_end is the index of the closing `/`
    and end is one past the last flag character. None when the construct
    hits a newline or EOF first, meaning it was not a regex.
    """
    n = len(text)
    j = i + 1
    in_class = False
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return None
        if in_class:
            if c == "]":
                in_class = False
            j += 1
            continue
        if c == "[":
            in_class = True
            j += 1
            continue
        if c == "/":
            k = j + 1
            while k < n and (text[k].isalpha()):
                k += 1
            return j, k
        j += 1
    return None


def scan(text: str, path: Path = Path("<memory>")) -> Source:
    """Lex an in-memory string. Never raises; sets ok=False on trouble."""
    n = len(text)
    line_starts = (0,) + tuple(i + 1 for i, c in enumerate(text) if c == "\n")
    if n == 0:
        return Source(path=path, text=text, masked="", ok=True, line_starts=line_starts)

    buf = list(text)
    ok = True
    i = 0

    # A shebang line is not JavaScript; blanking it stops `#!/usr/bin/env`
    # from being lexed as a regex literal.
    if text.startswith("#!"):
        nl = text.find("\n")
        stop = n if nl == -1 else nl
        _blank(buf, text, 0, stop)
        i = stop

    # Frames: [kind, brace_depth, is_substitution]. kind is "code" or "tmpl".
    stack: list[list] = [["code", 0, False]]
    guard = 0
    guard_limit = 4 * n + 4096

    while i < n:
        guard += 1
        if guard > guard_limit:  # pragma: no cover - defensive, cannot trigger
            ok = False
            break
        frame = stack[-1]

        if frame[0] == "tmpl":
            c = text[i]
            if c == "\\":
                _blank(buf, text, i, i + 2)
                i += 2
                continue
            if c == "`":
                stack.pop()
                i += 1
                continue
            if c == "$" and i + 1 < n and text[i + 1] == "{":
                stack.append(["code", 0, True])
                i += 2
                continue
            _blank(buf, text, i, i + 1)
            i += 1
            continue

        c = text[i]

        if c == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i)
            stop = n if nl == -1 else nl
            _blank(buf, text, i, stop)
            i = stop
            continue

        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                _blank(buf, text, i, n)
                ok = False
                i = n
                continue
            _blank(buf, text, i, end + 2)
            i = end + 2
            continue

        if c == "/":
            k = _prev_significant(buf, i)
            prevc = buf[k] if k >= 0 else ""
            # JSX: `</Foo>` and the self-closing `<Foo bar={x} />`. Both put a
            # `/` in what is otherwise a regex position; without this guard a
            # single .tsx render method desynchronises the whole file.
            jsx = (
                (prevc == "<" and _looks_like_jsx_close(text, i))
                or (prevc == "}" and text[i + 1:i + 2] == ">")
            )
            if not jsx and _in_regex_position(buf, i):
                found = _scan_regex(text, i)
                if found is not None:
                    body_end, end = found
                    _blank(buf, text, i + 1, body_end)
                    _blank(buf, text, body_end + 1, end)
                    i = end
                    continue
            i += 1
            continue

        if c == "'" or c == '"':
            j = i + 1
            closed = False
            hit_newline = False
            while j < n:
                d = text[j]
                if d == "\\":
                    j += 2
                    continue
                if d == "\n":
                    hit_newline = True
                    break
                if d == c:
                    closed = True
                    break
                j += 1
            if closed:
                _blank(buf, text, i + 1, j)
                i = j + 1
                continue
            if not hit_newline:
                # ran off the end of the file inside a quote
                ok = False
            i += 1
            continue

        if c == "`":
            stack.append(["tmpl"])
            i += 1
            continue

        if c == "{":
            frame[1] += 1
            i += 1
            continue

        if c == "}":
            if frame[2] and frame[1] == 0:
                stack.pop()
                i += 1
                continue
            frame[1] -= 1
            if frame[1] < 0:
                frame[1] = 0
                ok = False
            i += 1
            continue

        i += 1

    if len(stack) > 1:
        ok = False
    elif stack[0][1] != 0:
        ok = False

    return Source(path=path, text=text, masked="".join(buf), ok=ok, line_starts=line_starts)


# ==========================================================================
# discovery & loading (design §2)
# ==========================================================================
def _is_excluded_filename(path: Path) -> bool:
    n = path.name
    if n.endswith((".d.ts", ".d.mts", ".d.cts")):      # declarations: signatures, no bodies
        return True
    if ".min." in n or ".bundle." in n:                 # minified/bundled artifacts
        return True
    for marker in (".test.", ".spec.", ".examples.", ".stories."):
        if marker in n:
            return True
    return False


def iter_source_files(root: Path) -> Iterator[Path]:
    """Yield analyzable TS/JS files under root, in os-walk order.

    Directory pruning starts *at* root, so path components above root are
    never inspected — a fixture living under `tests/fixtures/` is still
    scanned when root points into it. Directory and file names are sorted
    so the output is byte-identical across runs.
    """
    root = Path(root)
    if root.is_file():
        if root.suffix in TS_EXTENSIONS and not _is_excluded_filename(root):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in TS_SKIP_DIRS)
        base = Path(dirpath)
        for name in sorted(filenames):
            p = base / name
            if p.suffix not in TS_EXTENSIONS:
                continue
            if _is_excluded_filename(p):
                continue
            yield p


def _looks_minified(text: str) -> bool:
    """True when the first 64 KB contains a line longer than 2000 chars."""
    head = text[:65536]
    start = 0
    while True:
        nl = head.find("\n", start)
        if nl == -1:
            return len(head) - start > 2000 and len(text) > 2000
        if nl - start > 2000:
            return True
        start = nl + 1


def load(path: Path, *, max_bytes: int = 1_500_000) -> Source | None:
    """Read + lex. Returns None on OSError, on a file over max_bytes, or
    when the file looks minified (see §2.3). Never raises."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        # errors="replace" (not a bare read_text) — a latin-1 .js file in the
        # wild must not raise UnicodeDecodeError, which is a ValueError and
        # would sail past the `except OSError` the six Python checks use.
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    except ValueError:  # pragma: no cover - errors="replace" makes this unreachable
        return None
    if len(text) > max_bytes:
        return None
    if _looks_minified(text):
        return None
    return scan(text, path)


# ==========================================================================
# brackets
# ==========================================================================
def match_bracket(src: Source, open_idx: int) -> int | None:
    """Index of the bracket closing the one at open_idx, or None."""
    m = src.masked
    n = len(m)
    if open_idx < 0 or open_idx >= n or m[open_idx] not in _OPEN:
        return None
    stack = [m[open_idx]]
    i = open_idx + 1
    while i < n:
        c = m[i]
        if c in _OPEN:
            stack.append(c)
        elif c in _CLOSE:
            if not stack or stack[-1] != _PAIR[c]:
                return None
            stack.pop()
            if not stack:
                return i
        i += 1
    return None


def _prev_sig_char(m: str, i: int, lo: int) -> str:
    k = i - 1
    while k >= lo and m[k] in _WS:
        k -= 1
    return m[k] if k >= lo else ""


def _split_top_level(src: Source, start: int, end: int, *, angles: bool = True) -> list[Span]:
    """Comma-split [start, end) at bracket (and optionally angle) depth 0."""
    m = src.masked
    spans: list[Span] = []
    depth = 0
    angle = 0
    seg = start
    i = start
    while i < end:
        c = m[i]
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            depth -= 1
            if depth < 0:
                depth = 0
        elif angles and depth == 0 and c == "<":
            p = _prev_sig_char(m, i, start)
            if p and (p.isalnum() or p in "_$>)]"):
                angle += 1
        elif angles and depth == 0 and c == ">":
            if angle > 0 and (i == 0 or m[i - 1] != "="):
                angle -= 1
        elif c == "," and depth == 0 and angle == 0:
            spans.append(Span(seg, i))
            seg = i + 1
        i += 1
    spans.append(Span(seg, end))
    if angles and angle != 0:
        # Angle tracking did not balance — it was comparison operators, not
        # generics. Redo without it rather than return a bogus split.
        return _split_top_level(src, start, end, angles=False)
    if len(spans) == 1 and src.trimmed(spans[0]).is_empty():
        return []
    return spans


def split_args(src: Source, open_paren: int) -> tuple[list[Span], int] | None:
    """Split the top-level comma-separated arguments of the paren group
    opening at open_paren. Returns (spans, close_idx). A trailing comma
    yields a trailing empty span — callers strip it (RECON A rule R1)."""
    m = src.masked
    if open_paren < 0 or open_paren >= len(m) or m[open_paren] != "(":
        return None
    close = match_bracket(src, open_paren)
    if close is None:
        return None
    return _split_top_level(src, open_paren + 1, close), close


# ==========================================================================
# calls
# ==========================================================================
_CHAIN_RE = re.compile(
    r"(?P<chain>[A-Za-z_$][A-Za-z0-9_$]*(?:\s*\??\.\s*[A-Za-z_$][A-Za-z0-9_$]*)*)"
    r"(?P<generic>\s*<[^<>;{}()\n]*>)?"
    r"(?:\s*\?\.)?"
    r"\s*\("
)


def _normalize_chain(raw: str) -> str:
    return re.sub(r"\s+", "", raw).replace("?.", ".")


def _build_callsite(src: Source, m: re.Match[str], *, is_new: bool,
                    start_override: int | None = None) -> CallSite | None:
    masked = src.masked
    open_paren = m.end() - 1
    got = split_args(src, open_paren)
    if got is None:
        return None
    args, close = got
    chain = _normalize_chain(m.group("chain"))
    parts = chain.split(".")
    method = parts[-1]
    receiver = ".".join(parts[:-1])
    root = parts[0]

    name_start = m.start("chain")
    if not receiver:
        # `foo().rm(x)` / `arr[0].exec(y)`: the chain regex can only see the
        # last segment. Mark the receiver unknown rather than pretending this
        # is a bare call — a bare `rm(` is import-resolvable and this is not.
        if _prev_sig_char(masked, name_start, 0) == ".":
            receiver = UNKNOWN_RECEIVER
            root = UNKNOWN_RECEIVER
    callee = (receiver + "." + method) if receiver else method

    span_start = name_start if start_override is None else start_override
    return CallSite(
        callee=callee,
        method=method,
        receiver=receiver,
        root=root,
        is_new=is_new,
        name_span=Span(name_start, m.end("chain")),
        args_span=Span(open_paren + 1, close),
        call_span=Span(span_start, close + 1),
        args=tuple(args),
        line=src.line_of(name_start),
    )


def _preceding_word(masked: str, offset: int) -> str:
    k = _prev_sig_char_index(masked, offset)
    if k < 0:
        return ""
    if not (masked[k].isalnum() or masked[k] in "_$"):
        return ""
    j = k
    while j >= 0 and (masked[j].isalnum() or masked[j] in "_$"):
        j -= 1
    word = masked[j + 1:k + 1]
    return word if _IDENT_FULL_RE.match(word) else ""


def _prev_sig_char_index(m: str, i: int) -> int:
    k = i - 1
    while k >= 0 and m[k] in _WS:
        k -= 1
    return k


def find_calls(src: Source, methods: Collection[str], *,
               within: Span | None = None) -> list[CallSite]:
    """Every call whose callee's LAST dotted segment is in `methods`.

    Matches `x.y.rm(...)`, `rm(...)`, `x?.rm(...)`, and TS generic call
    forms `f<T>(...)`. Excludes declarations (`function rm(`, `class X(`),
    control-flow keywords (`if`, `for`, `while`, `switch`, `catch`,
    `return`, `typeof`, `await`, `super`), and `new X(...)` — constructions
    are reported by `find_constructions` instead.

    When the receiver is not a plain identifier chain (`foo().rm(x)`),
    `receiver` and `root` are `UNKNOWN_RECEIVER` ("?"): the call is still
    returned, but it can never resolve against an import binding.
    """
    wanted = set(methods)
    if not wanted or not src.masked:
        return []
    out: list[CallSite] = []
    lo = 0 if within is None else max(0, within.start)
    hi = len(src.masked) if within is None else min(len(src.masked), within.end)
    for m in _CHAIN_RE.finditer(src.masked, lo, hi):
        chain = _normalize_chain(m.group("chain"))
        parts = chain.split(".")
        if parts[-1] not in wanted:
            continue
        if len(parts) == 1 and parts[0] in _CALL_KEYWORDS:
            continue
        prev_word = _preceding_word(src.masked, m.start("chain"))
        if prev_word in ("function", "class", "new"):
            continue
        cs = _build_callsite(src, m, is_new=False)
        if cs is not None:
            out.append(cs)
    return out


def find_constructions(src: Source, class_names: Collection[str], *,
                       within: Span | None = None) -> list[CallSite]:
    """`new X(...)` sites. Matches on the last dotted segment of X."""
    wanted = set(class_names)
    if not wanted or not src.masked:
        return []
    out: list[CallSite] = []
    lo = 0 if within is None else max(0, within.start)
    hi = len(src.masked) if within is None else min(len(src.masked), within.end)
    for nm in re.finditer(r"(?<![\w$])new(?![\w$])", src.masked):
        if nm.start() < lo or nm.start() >= hi:
            continue
        m = _CHAIN_RE.match(src.masked, _skip_ws(src.masked, nm.end(), hi))
        if m is None:
            continue
        chain = _normalize_chain(m.group("chain"))
        if chain.split(".")[-1] not in wanted:
            continue
        cs = _build_callsite(src, m, is_new=True, start_override=nm.start())
        if cs is not None:
            out.append(cs)
    return out


# ==========================================================================
# functions
# ==========================================================================
def _skip_ws(m: str, i: int, limit: int) -> int:
    while i < limit and m[i] in _WS:
        i += 1
    return i


def _word_at(m: str, i: int, limit: int) -> tuple[str, int]:
    if i >= limit or not (m[i].isalpha() or m[i] in "_$"):
        return "", i
    j = i
    while j < limit and (m[j].isalnum() or m[j] in "_$"):
        j += 1
    return m[i:j], j


def _expression_end(src: Source, start: int, limit: int) -> int:
    """End offset of the expression beginning at `start`, bounded by limit."""
    m = src.masked
    depth = 0
    i = start
    while i < limit:
        c = m[i]
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            if depth == 0:
                break
            depth -= 1
        elif depth == 0:
            if c in ";,":
                break
            if c == "\n":
                j = _skip_ws(m, i + 1, limit)
                if j >= limit:
                    break
                nc = m[j]
                if nc in _CONTINUATION_CHARS:
                    i = j
                    continue
                word, _ = _word_at(m, j, limit)
                if word in _CONTINUATION_WORDS:
                    i = j
                    continue
                break
        i += 1
    while i > start and m[i - 1] in _WS:
        i -= 1
    return i


def _after_params(src: Source, k: int, limit: int) -> tuple[str, int] | None:
    """From just after a parameter list's `)`, find `=>` or the body `{`.

    Returns ("arrow", offset_of_arrow) or ("brace", offset_of_brace).
    Skips a return-type annotation, including an object-type literal.
    """
    m = src.masked
    window = min(limit, k + 4000)
    p = k
    depth = 0
    rounds = 0
    while p < window and rounds < 8:
        c = m[p]
        if c == "{" and depth == 0:
            close = match_bracket(src, p)
            if close is None:
                return None
            nxt = _skip_ws(m, close + 1, window)
            if m[nxt:nxt + 2] == "=>":
                # that brace was an object-type annotation; keep looking
                p = nxt
                rounds += 1
                continue
            return "brace", p
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            if depth == 0:
                return None
            depth -= 1
        elif depth == 0:
            if c == "=" and m[p:p + 2] == "=>":
                return "arrow", p
            if c in ";,":
                return None
        p += 1
    return None


def _parse_function_at(src: Source, start: int, limit: int, *,
                       allow_method: bool = True) -> FunctionBody | None:
    m = src.masked
    limit = min(limit, len(m))
    i = _skip_ws(m, start, limit)
    if i >= limit:
        return None
    real_start = i
    is_async = False

    word, after = _word_at(m, i, limit)
    if word == "async":
        k = _skip_ws(m, after, limit)
        if k < limit and (m[k] == "(" or m[k:k + 8] == "function"
                          or m[k].isalpha() or m[k] in "_$"):
            is_async = True
            i = k
            word, after = _word_at(m, i, limit)

    params_span: Span | None = None
    kind: str
    body_span: Span
    body_is_expression: bool
    end: int

    if word == "function":
        j = _skip_ws(m, after, limit)
        if j < limit and m[j] == "*":
            j = _skip_ws(m, j + 1, limit)
        nm, j2 = _word_at(m, j, limit)
        if nm:
            j = _skip_ws(m, j2, limit)
        if j >= limit or m[j] != "(":
            return None
        close = match_bracket(src, j)
        if close is None or close >= limit:
            return None
        params_span = Span(j + 1, close)
        got = _after_params(src, close + 1, limit)
        if got is None or got[0] != "brace":
            return None
        bopen = got[1]
        bclose = match_bracket(src, bopen)
        if bclose is None or bclose >= limit:
            return None
        kind = "function"
        body_span = Span(bopen + 1, bclose)
        body_is_expression = False
        end = bclose + 1

    elif i < limit and m[i] == "(":
        close = match_bracket(src, i)
        if close is None or close >= limit:
            return None
        params_span = Span(i + 1, close)
        got = _after_params(src, close + 1, limit)
        if got is None:
            return None
        what, pos = got
        if what == "arrow":
            kind = "arrow"
            b = _skip_ws(m, pos + 2, limit)
            if b < limit and m[b] == "{":
                bclose = match_bracket(src, b)
                if bclose is None or bclose >= limit:
                    return None
                body_span = Span(b + 1, bclose)
                body_is_expression = False
                end = bclose + 1
            else:
                e = _expression_end(src, b, limit)
                body_span = Span(b, e)
                body_is_expression = True
                end = e
        else:
            if not allow_method:
                return None
            bclose = match_bracket(src, pos)
            if bclose is None or bclose >= limit:
                return None
            kind = "method"
            body_span = Span(pos + 1, bclose)
            body_is_expression = False
            end = bclose + 1

    elif word:
        if word in _CALL_KEYWORDS and word != "async":
            return None
        k = _skip_ws(m, after, limit)
        if m[k:k + 2] != "=>":
            return None
        params_span = Span(i, after)
        kind = "arrow"
        b = _skip_ws(m, k + 2, limit)
        if b < limit and m[b] == "{":
            bclose = match_bracket(src, b)
            if bclose is None or bclose >= limit:
                return None
            body_span = Span(b + 1, bclose)
            body_is_expression = False
            end = bclose + 1
        else:
            e = _expression_end(src, b, limit)
            body_span = Span(b, e)
            body_is_expression = True
            end = e
    else:
        return None

    params, positional, ok = parse_params(src, params_span)
    return FunctionBody(
        kind=kind,
        is_async=is_async,
        params=params,
        positional_count=positional,
        params_ok=ok,
        params_span=params_span,
        body_span=body_span,
        body_is_expression=body_is_expression,
        span=Span(real_start, end),
        line=src.line_of(real_start),
    )


def function_in_span(src: Source, span: Span) -> FunctionBody | None:
    """Parse span (after trimming, and after peeling one layer of wrapping
    parens) as a single function expression. Returns None when the span is
    an identifier, a call, an object, or anything else. This is the
    workhorse for 'is this call argument a handler?'."""
    s = src.trimmed(span)
    if s.is_empty():
        return None
    m = src.masked
    for _ in range(4):
        if m[s.start] != "(":
            break
        close = match_bracket(src, s.start)
        if close is None or close != s.end - 1:
            break
        s = src.trimmed(Span(s.start + 1, s.end - 1))
        if s.is_empty():
            return None
    return _parse_function_at(src, s.start, s.end)


def find_functions(src: Source, within: Span) -> list[FunctionBody]:
    """Every arrow/function expression starting inside `within`, outermost
    first, then by offset. Used for the wrapped-handler case
    (mcp-playwright's loggingMiddleware.wrapHandler)."""
    m = src.masked
    lo = max(0, within.start)
    hi = min(len(m), within.end)
    if lo >= hi:
        return []

    candidates: list[int] = []
    for mt in re.finditer(r"(?<![\w$])(?:async(?![\w$])\s*)?function(?![\w$])", m):
        if lo <= mt.start() < hi:
            candidates.append(mt.start())
    for mt in re.finditer(r"(?<![\w$])async(?![\w$])", m):
        if lo <= mt.start() < hi:
            candidates.append(mt.start())
    for idx, ch in enumerate(m[lo:hi], start=lo):
        if ch == "(":
            candidates.append(idx)
    for mt in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=>", m):
        if lo <= mt.start(1) < hi:
            candidates.append(mt.start(1))

    candidates = sorted(set(candidates))
    if len(candidates) > 5000:  # pragma: no cover - defensive bound
        candidates = candidates[:5000]

    found: dict[int, FunctionBody] = {}
    for c in candidates:
        fb = _parse_function_at(src, c, hi, allow_method=False)
        if fb is None:
            continue
        key = fb.body_span.start
        prev = found.get(key)
        if prev is None or fb.span.start < prev.span.start:
            found[key] = fb
    return sorted(found.values(), key=lambda f: (f.span.start, -f.span.end))


# ==========================================================================
# parameters (design §1.6)
# ==========================================================================
def _rightmost_default_eq(m: str, start: int, end: int) -> int:
    """Index of the rightmost `=` at depth 0 in [start, end) that is an
    assignment (not `=>`, `==`, `===`, `<=`, `>=`, `!=`), or -1."""
    depth = 0
    best = -1
    i = start
    while i < end:
        c = m[i]
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            depth -= 1
            if depth < 0:
                depth = 0
        elif c == "=" and depth == 0:
            nxt = m[i + 1] if i + 1 < end else ""
            prv = m[i - 1] if i > start else ""
            if nxt not in ("=", ">") and prv not in ("=", "!", "<", ">"):
                best = i
        i += 1
    return best


def _rightmost_colon(m: str, start: int, end: int) -> int:
    depth = 0
    best = -1
    i = start
    while i < end:
        c = m[i]
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            depth -= 1
            if depth < 0:
                depth = 0
        elif c == ":" and depth == 0:
            best = i
        i += 1
    return best


def _first_colon(m: str, start: int, end: int) -> int:
    depth = 0
    i = start
    while i < end:
        c = m[i]
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            depth -= 1
            if depth < 0:
                depth = 0
        elif c == ":" and depth == 0:
            return i
        i += 1
    return -1


def _is_plain_identifier(text: str) -> bool:
    t = text.strip()
    return bool(t) and _IDENT_FULL_RE.match(t) is not None


def parse_params(src: Source, params_span: Span) -> tuple[tuple[Param, ...], int, bool]:
    """(bindings, positional_count, ok). ok=False on array destructuring,
    nested patterns we cannot flatten, or any parse we are unsure of."""
    if params_span is None:
        return (), 0, True
    s = src.trimmed(params_span)
    if s.is_empty():
        return (), 0, True

    m = src.masked
    slices = _split_top_level(src, s.start, s.end)
    # drop a single trailing empty slice (trailing comma)
    if slices and src.trimmed(slices[-1]).is_empty():
        slices = slices[:-1]

    params: list[Param] = []
    ok = True
    index = 0
    for raw_slice in slices:
        sl = src.trimmed(raw_slice)
        if sl.is_empty():
            ok = False
            continue

        # 1. strip a trailing default
        eq = _rightmost_default_eq(m, sl.start, sl.end)
        if eq != -1:
            sl = src.trimmed(Span(sl.start, eq))
        # 2. strip a trailing type annotation
        type_text = ""
        colon = _rightmost_colon(m, sl.start, sl.end)
        if colon != -1:
            type_span = src.trimmed(Span(colon + 1, sl.end))
            type_text = re.sub(r"\s+", " ", src.raw(type_span)).strip()
            sl = src.trimmed(Span(sl.start, colon))
        if sl.is_empty():
            ok = False
            index += 1
            continue

        head = m[sl.start]
        body = m[sl.start:sl.end]

        # 3. rest parameter
        if body.startswith("..."):
            inner = src.trimmed(Span(sl.start + 3, sl.end))
            name = src.raw(inner).strip()
            if not _is_plain_identifier(name):
                ok = False
            else:
                params.append(Param(name=name, source_name=name, index=index,
                                    is_rest=True, is_destructured=False,
                                    span=inner, type_text=type_text))
            index += 1
            continue

        # 5. array destructuring: hard suppress
        if head == "[":
            ok = False
            index += 1
            continue

        # 4. object destructuring
        if head == "{":
            close = match_bracket(src, sl.start)
            if close is None or close != sl.end - 1:
                ok = False
                index += 1
                continue
            entries = _split_top_level(src, sl.start + 1, close)
            for ent_raw in entries:
                ent = src.trimmed(ent_raw)
                if ent.is_empty():
                    continue
                etext = m[ent.start:ent.end]
                if etext.startswith("..."):
                    inner = src.trimmed(Span(ent.start + 3, ent.end))
                    nm = src.raw(inner).strip()
                    if not _is_plain_identifier(nm):
                        ok = False
                        continue
                    params.append(Param(name=nm, source_name=nm, index=index,
                                        is_rest=True, is_destructured=True,
                                        span=inner, type_text=""))
                    continue
                eq2 = _rightmost_default_eq(m, ent.start, ent.end)
                if eq2 != -1:
                    ent = src.trimmed(Span(ent.start, eq2))
                if ent.is_empty():
                    ok = False
                    continue
                col2 = _first_colon(m, ent.start, ent.end)
                if col2 != -1:
                    key_span = src.trimmed(Span(ent.start, col2))
                    loc_span = src.trimmed(Span(col2 + 1, ent.end))
                    key = src.raw(key_span).strip()
                    loc = src.raw(loc_span).strip()
                    if not _is_plain_identifier(loc) or not _is_plain_identifier(key):
                        # computed key, nested pattern, array pattern
                        ok = False
                        continue
                    params.append(Param(name=loc, source_name=key, index=index,
                                        is_rest=False, is_destructured=True,
                                        span=loc_span, type_text=""))
                else:
                    nm = src.raw(ent).strip()
                    if not _is_plain_identifier(nm):
                        ok = False
                        continue
                    params.append(Param(name=nm, source_name=nm, index=index,
                                        is_rest=False, is_destructured=True,
                                        span=ent, type_text=""))
            index += 1
            continue

        # 6. plain identifier
        name = src.raw(sl).strip()
        if not _is_plain_identifier(name):
            ok = False
        else:
            params.append(Param(name=name, source_name=name, index=index,
                                is_rest=False, is_destructured=False,
                                span=sl, type_text=type_text))
        index += 1

    return tuple(params), index, ok


# ==========================================================================
# objects
# ==========================================================================
def _unquote_key(raw: str) -> str:
    r = raw.strip()
    if len(r) >= 2 and r[0] == r[-1] and r[0] in "'\"":
        return r[1:-1]
    return r


def parse_object(src: Source, span: Span) -> ObjectLiteral | None:
    """Parse span (trimmed) as an object literal. None if it isn't one."""
    s = src.trimmed(span)
    if s.is_empty():
        return None
    m = src.masked
    if m[s.start] != "{":
        return None
    close = match_bracket(src, s.start)
    if close is None or close != s.end - 1:
        return None

    entries: list[ObjectEntry] = []
    ok = True
    has_spread = False
    for raw_ent in _split_top_level(src, s.start + 1, close):
        ent = src.trimmed(raw_ent)
        if ent.is_empty():
            continue
        etext = m[ent.start:ent.end]
        line = src.line_of(ent.start)

        if etext.startswith("..."):
            has_spread = True
            entries.append(ObjectEntry(key="", key_span=ent,
                                       value_span=src.trimmed(Span(ent.start + 3, ent.end)),
                                       is_shorthand=False, is_method=False,
                                       is_spread=True, line=line))
            continue

        colon = _first_colon(m, ent.start, ent.end)
        if colon != -1:
            key_span = src.trimmed(Span(ent.start, colon))
            value_span = src.trimmed(Span(colon + 1, ent.end))
            key_raw = src.raw(key_span).strip()
            key = "" if key_raw.startswith("[") else _unquote_key(key_raw)
            if key and not (_is_plain_identifier(key) or key_raw[0] in "'\"" or key.isdigit()):
                ok = False
            entries.append(ObjectEntry(key=key, key_span=key_span, value_span=value_span,
                                       is_shorthand=False, is_method=False,
                                       is_spread=False, line=line))
            continue

        # method shorthand: `handler(a, b) { ... }`, `async run() {}`, `get x() {}`
        paren = _find_top_level_char(src, ent.start, ent.end, "(")
        if paren != -1:
            prefix = src.trimmed(Span(ent.start, paren))
            words = src.raw(prefix).replace("*", " ").split()
            while words and words[0] in ("async", "get", "set", "static"):
                words.pop(0)
            name = words[-1] if words else ""
            name = _unquote_key(name)
            if not name or name.startswith("["):
                name = ""
            entries.append(ObjectEntry(key=name, key_span=prefix,
                                       value_span=Span(paren, ent.end),
                                       is_shorthand=False, is_method=True,
                                       is_spread=False, line=line))
            continue

        name = src.raw(ent).strip()
        if not _is_plain_identifier(name):
            ok = False
            continue
        entries.append(ObjectEntry(key=name, key_span=ent,
                                   value_span=Span(ent.end, ent.end),
                                   is_shorthand=True, is_method=False,
                                   is_spread=False, line=line))

    return ObjectLiteral(span=Span(s.start, close + 1), entries=tuple(entries),
                         has_spread=has_spread, ok=ok)


def _find_top_level_char(src: Source, start: int, end: int, target: str) -> int:
    m = src.masked
    depth = 0
    i = start
    while i < end:
        c = m[i]
        if c == target and depth == 0:
            return i
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            depth -= 1
            if depth < 0:
                depth = 0
        i += 1
    return -1


# ==========================================================================
# module structure
# ==========================================================================
_ESM_FROM_RE = re.compile(
    r"(?<![\w$])import\s+(?P<clause>[^;()`]*?)\s+from\s*(?P<q>['\"])"
)
_ESM_BARE_RE = re.compile(r"(?<![\w$])import\s*(?P<q>['\"])")
_REQUIRE_RE = re.compile(
    r"(?<![\w$])(?:const|let|var)\s+(?P<lhs>[^=;]+?)\s*=\s*require\s*\(\s*(?P<q>['\"])"
)


def _string_at(src: Source, quote_idx: int) -> str | None:
    """Raw contents of the string literal whose opening quote is at
    quote_idx, or None when it is not a well-formed literal."""
    m = src.masked
    if quote_idx >= len(m) or m[quote_idx] not in "'\"":
        return None
    q = m[quote_idx]
    close = m.find(q, quote_idx + 1)
    if close == -1 or close - quote_idx > 512:
        return None
    body = src.text[quote_idx + 1:close]
    if "\n" in body:
        return None
    return body


def string_literal_value(src: Source, span: Span) -> str | None:
    """The value of a span that is exactly a single-quoted / double-quoted
    string literal, or a template literal with no `${}` holes. None
    otherwise. (Convenience for checks needing a tool name.)"""
    s = src.trimmed(span)
    if s.is_empty():
        return None
    m = src.masked
    c = m[s.start]
    if c in "'\"":
        if m[s.end - 1] != c or s.end - s.start < 2:
            return None
        if m.find(c, s.start + 1) != s.end - 1:
            return None
        return src.text[s.start + 1:s.end - 1]
    if c == "`":
        if s.end - s.start < 2 or m[s.end - 1] != "`":
            return None
        body_masked = m[s.start + 1:s.end - 1]
        if "`" in body_masked or "${" in body_masked:
            return None
        return src.text[s.start + 1:s.end - 1]
    return None


def _parse_named_specifiers(inner: str) -> list[tuple[str, str, bool]]:
    """`{ a, b as c, type D }` interior -> [(imported, local, type_only)]."""
    out: list[tuple[str, str, bool]] = []
    for part in inner.split(","):
        p = part.strip()
        if not p:
            continue
        type_only = False
        if p.startswith("type "):
            type_only = True
            p = p[5:].strip()
        bits = re.split(r"\s+as\s+", p)
        if len(bits) == 2:
            imported, local = bits[0].strip(), bits[1].strip()
        else:
            imported = local = p
        if not imported or not local:
            continue
        out.append((imported, local, type_only))
    return out


def collect_imports(src: Source) -> list[ImportRecord]:
    """ESM `import` in all forms, plus CommonJS
    `const x = require('m')` / `const { a, b: c } = require('m')`.
    Dynamic `import('m')` is ignored.

    A `require('m')` namespace object is recorded with imported="*".
    A bare side-effect `import 'm'` is recorded with local="" — it binds
    nothing but it still proves the module is in play.
    """
    out: list[ImportRecord] = []
    m = src.masked

    for mt in _ESM_FROM_RE.finditer(m):
        module = _string_at(src, mt.start("q"))
        if module is None:
            continue
        line = src.line_of(mt.start())
        clause = mt.group("clause").strip()
        type_only = False
        if clause.startswith("type ") or clause.startswith("type\n"):
            type_only = True
            clause = clause[4:].strip()
        if not clause:
            out.append(ImportRecord(module=module, local="", imported="",
                                    is_type_only=type_only, line=line))
            continue
        # split the clause into its top-level pieces
        pieces: list[str] = []
        depth = 0
        buf = []
        for ch in clause:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            if ch == "," and depth == 0:
                pieces.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
        pieces.append("".join(buf))
        for piece in pieces:
            p = piece.strip()
            if not p:
                continue
            if p.startswith("*"):
                rest = p[1:].strip()
                if rest.startswith("as"):
                    rest = rest[2:].strip()
                local = rest
                if _is_plain_identifier(local):
                    out.append(ImportRecord(module=module, local=local, imported="*",
                                            is_type_only=type_only, line=line))
            elif p.startswith("{"):
                inner = p[1:-1] if p.endswith("}") else p[1:]
                for imported, local, t in _parse_named_specifiers(inner):
                    out.append(ImportRecord(module=module, local=local, imported=imported,
                                            is_type_only=type_only or t, line=line))
            elif _is_plain_identifier(p):
                out.append(ImportRecord(module=module, local=p, imported="default",
                                        is_type_only=type_only, line=line))

    for mt in _ESM_BARE_RE.finditer(m):
        module = _string_at(src, mt.start("q"))
        if module is None:
            continue
        out.append(ImportRecord(module=module, local="", imported="",
                                is_type_only=False, line=src.line_of(mt.start())))

    for mt in _REQUIRE_RE.finditer(m):
        module = _string_at(src, mt.start("q"))
        if module is None:
            continue
        line = src.line_of(mt.start())
        lhs = mt.group("lhs").strip()
        if lhs.startswith("{"):
            inner = lhs[1:-1] if lhs.endswith("}") else lhs[1:]
            for part in inner.split(","):
                p = part.strip()
                if not p:
                    continue
                if ":" in p:
                    imported, local = (x.strip() for x in p.split(":", 1))
                else:
                    imported = local = p
                if _is_plain_identifier(local) and _is_plain_identifier(imported):
                    out.append(ImportRecord(module=module, local=local, imported=imported,
                                            is_type_only=False, line=line))
        elif _is_plain_identifier(lhs):
            out.append(ImportRecord(module=module, local=lhs, imported="*",
                                    is_type_only=False, line=line))

    out.sort(key=lambda r: (r.line, r.local, r.imported))
    return out


_VAR_DECL_RE = re.compile(
    r"(?<![\w$])(?P<kind>const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*"
    r"(?::(?P<type>[^=;\n]*))?=(?!=)"
)
_FUNC_DECL_RE = re.compile(
    r"(?<![\w$])(?:async\s+)?function(?![\w$])\s*\*?\s*(?P<name>[A-Za-z_$][\w$]*)"
)
_CLASS_DECL_RE = re.compile(r"(?<![\w$])class(?![\w$])\s+(?P<name>[A-Za-z_$][\w$]*)")


def collect_bindings(src: Source) -> dict[str, Binding]:
    """Top-level `const`/`let`/`var`/`function`/`class` declarations, by
    name. First declaration wins (mirrors command_injection's setdefault).

    "Top-level" means brace depth 0 in the masked text. A `const` declared
    inside `async function main() { ... }` is deliberately NOT collected —
    resolving it would need scope tracking we do not have, and a wrong
    resolution is a false positive.
    """
    m = src.masked
    n = len(m)
    cands: list[tuple[int, str, re.Match[str]]] = []
    for mt in _VAR_DECL_RE.finditer(m):
        cands.append((mt.start(), "var", mt))
    for mt in _FUNC_DECL_RE.finditer(m):
        cands.append((mt.start(), "function", mt))
    for mt in _CLASS_DECL_RE.finditer(m):
        cands.append((mt.start(), "class", mt))
    cands.sort(key=lambda t: t[0])

    out: dict[str, Binding] = {}
    depth = 0
    pos = 0
    for offset, family, mt in cands:
        while pos < offset and pos < n:
            c = m[pos]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth < 0:
                    depth = 0
            pos += 1
        if depth != 0:
            continue
        name = mt.group("name")
        if name in out:
            continue
        if family == "var":
            start = mt.end()
            end = _expression_end(src, _skip_ws(m, start, n), n)
            value = Span(_skip_ws(m, start, n), end)
            kind = mt.group("kind")
        elif family == "function":
            fb = _parse_function_at(src, offset, n)
            value = fb.span if fb is not None else Span(offset, offset)
            kind = "function"
        else:
            brace = _find_next_brace(src, mt.end(), n)
            if brace == -1:
                value = Span(offset, offset)
            else:
                close = match_bracket(src, brace)
                value = Span(offset, close + 1 if close is not None else brace)
            kind = "class"
        out[name] = Binding(name=name, kind=kind, value_span=value,
                            line=src.line_of(offset))
    return out


def _find_next_brace(src: Source, start: int, limit: int) -> int:
    m = src.masked
    i = start
    while i < limit:
        if m[i] == "{":
            return i
        i += 1
    return -1


def resolve_span(src: Source, name: str, bindings: Mapping[str, Binding],
                 *, depth: int = 2) -> Span | None:
    """Follow `const A = B; const B = {...}` up to `depth` hops. None when
    unresolvable — callers MUST suppress rather than guess."""
    seen: set[str] = set()
    cur = name
    for _ in range(max(1, depth + 1)):
        if cur in seen:
            return None
        seen.add(cur)
        b = bindings.get(cur)
        if b is None or b.value_span.is_empty():
            return None
        t = src.trimmed(b.value_span)
        if t.is_empty():
            return None
        txt = src.code(t)
        if _IDENT_FULL_RE.match(txt) and txt not in _CALL_KEYWORDS:
            cur = txt
            continue
        return t
    return None


# ==========================================================================
# identifiers
# ==========================================================================
def _token_re(tokens: Collection[str]) -> re.Pattern[str] | None:
    toks = sorted({t for t in tokens if t})
    if not toks:
        return None
    body = "|".join(re.escape(t) for t in toks)
    return re.compile(rf"(?<![\w$])(?:{body})(?![\w$])")


def identifier_uses(src: Source, within: Span, name: str) -> list[int]:
    """Offsets of `name` used as a value inside `within`. Word-bounded.

    EXCLUDES uses in property position (preceded by `.` or `?.`) and in
    object-literal key position (`{ name: ... }`), because `foo.args` and
    `{ path: x }` are not references to a local called `args`/`path`.
    """
    if not name:
        return []
    m = src.masked
    lo = max(0, within.start)
    hi = min(len(m), within.end)
    if lo >= hi:
        return []
    pat = re.compile(rf"(?<![\w$]){re.escape(name)}(?![\w$])")
    out: list[int] = []
    for mt in pat.finditer(m, lo, hi):
        i = mt.start()
        k = _prev_sig_char_index(m, i)
        prev = m[k] if k >= 0 else ""
        if prev == ".":
            continue
        if prev == "?" and k >= 1 and m[k - 1:k + 1] == "?.":
            continue
        # object-literal key position: `{ name: ...` / `, name: ...`
        j = _skip_ws(m, mt.end(), hi)
        if j < hi and m[j] == ":" and m[j:j + 2] != "::":
            if prev in ("{", ",", ""):
                continue
        out.append(i)
    return out


def contains_token(src: Source, within: Span, tokens: Collection[str]) -> bool:
    """True if any of `tokens` appears as a word-bounded identifier or
    `.member` inside `within`. Used by the guard-suppression predicates."""
    pat = _token_re(tokens)
    if pat is None:
        return False
    lo = max(0, within.start)
    hi = min(len(src.masked), within.end)
    if lo >= hi:
        return False
    return pat.search(src.masked, lo, hi) is not None
