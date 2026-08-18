"""Tests for jsparse — the masking lexer and TS/JS structural helpers.

The lexer is the foundation every TypeScript check stands on: if the mask
desynchronises, every span downstream is garbage and a check can anchor a
finding to nonsense. So the traps get first-class coverage here — strings
that look like comments, comments that look like strings, template holes,
nested templates, regex-vs-division, and every way a file can be truncated
mid-construct.
"""
from __future__ import annotations

from pathlib import Path

from mcp_audit import jsparse
from mcp_audit.jsparse import Span, scan


def _mask(text: str) -> str:
    return scan(text).masked


# ==========================================================================
# invariants
# ==========================================================================
def test_mask_is_always_the_same_length_as_the_source():
    for text in (
        "",
        "const a = 1;",
        "// comment\n/* block */\n`tpl ${x}`\n'str'\n\"str\"\n/re/g\n",
        "const t = `a${`b${c}`}d`;",
        "/* unterminated",
        "const s = 'unterminated",
        "const t = `unterminated ${x",
        "\u00e9\u4e2d\ufffd binary-ish \x00 bytes",
    ):
        src = scan(text)
        assert len(src.masked) == len(src.text) == len(text), repr(text)


def test_newlines_are_never_blanked():
    src = scan("/* one\ntwo\nthree */\nconst a = 1;\n")
    assert src.masked.count("\n") == src.text.count("\n")


def test_line_of_is_one_based_and_clamped():
    src = scan("a\nbb\nccc")
    assert src.line_of(0) == 1
    assert src.line_of(1) == 1     # the newline itself belongs to line 1
    assert src.line_of(2) == 2
    assert src.line_of(5) == 3
    assert src.line_of(-10) == 1
    assert src.line_of(10_000) == 3


def test_raw_code_and_trimmed():
    src = scan("  const s = 'secret';  ")
    span = Span(0, len(src.text))
    assert src.raw(span) == "  const s = 'secret';  "
    assert "secret" not in src.code(span)
    t = src.trimmed(span)
    assert src.raw(t) == "const s = 'secret';"


def test_span_semantics():
    s = Span(3, 7)
    assert len(s) == 4
    assert 3 in s and 6 in s and 7 not in s
    assert not s.is_empty()
    assert Span(5, 5).is_empty()
    assert len(Span(9, 4)) == 0


# ==========================================================================
# lexing traps
# ==========================================================================
def test_a_string_containing_a_double_slash_does_not_start_a_comment():
    src = scan('const url = "https://example.com/x";\nconst after = 1;\n')
    assert src.ok
    # the URL body is blanked, but the code after it survives
    assert "example.com" not in src.masked
    assert "const after = 1;" in src.masked


def test_a_string_containing_a_block_comment_opener_does_not_start_a_comment():
    src = scan('const g = "/* not a comment";\nconst after = 2;\n')
    assert src.ok
    assert "const after = 2;" in src.masked
    assert "not a comment" not in src.masked


def test_a_comment_containing_a_quote_does_not_start_a_string():
    src = scan("// it's fine\nconst after = 3;\n")
    assert src.ok
    assert "const after = 3;" in src.masked
    assert "fine" not in src.masked


def test_a_block_comment_containing_quotes_and_braces_is_inert():
    src = scan('/* don\'t { open " anything */\nif (x) { y(); }\n')
    assert src.ok
    assert "anything" not in src.masked
    open_brace = src.masked.index("{")
    assert jsparse.match_bracket(src, open_brace) == src.masked.index("}")


def test_line_comment_ends_at_the_newline_not_the_file():
    src = scan("const a = 1; // note\nconst b = 2;\n")
    assert "note" not in src.masked
    assert "const b = 2;" in src.masked


def test_template_literal_text_is_blanked_but_the_hole_stays_live():
    src = scan("const t = `git checkout ${branch} now`;")
    assert src.ok
    assert "git checkout" not in src.masked
    assert "${branch}" in src.masked
    assert "now" not in src.masked


def test_nested_template_literals_keep_both_holes_live():
    src = scan("const t = `a${`b${inner}c`}d`;")
    assert src.ok
    assert "${inner}" in src.masked
    assert "a" not in src.masked.replace("const", "")  # literal chunks gone
    # both holes analysable => the outer hole's braces still balance
    open_brace = src.masked.index("{")
    assert jsparse.match_bracket(src, open_brace) is not None


def test_template_literal_with_escaped_backtick_does_not_terminate_early():
    src = scan("const t = `a\\`b ${x}`;\nconst after = 4;\n")
    assert src.ok
    assert "${x}" in src.masked
    assert "const after = 4;" in src.masked


def test_a_comma_inside_a_template_literal_does_not_split_arguments():
    src = scan("f(`a,b`, second)")
    args, _ = jsparse.split_args(src, src.masked.index("("))
    assert len(args) == 2
    assert src.raw(src.trimmed(args[1])) == "second"


def test_escaped_quotes_and_trailing_backslash_inside_strings():
    src = scan('const a = "he said \\"hi\\"";\nconst b = \'c:\\\\path\\\\\';\nconst after = 5;\n')
    assert src.ok
    assert "he said" not in src.masked
    assert "const after = 5;" in src.masked


def test_regex_literal_with_slashes_and_braces_does_not_break_bracket_matching():
    src = scan("const r = /[/{}]+/g;\nif (x) { y(); }\n")
    assert src.ok
    open_brace = src.masked.index("{")
    assert jsparse.match_bracket(src, open_brace) == src.masked.index("}")


def test_regex_literal_containing_a_quote_is_blanked():
    src = scan("const q = /['\"]/;\nconst after = 6;\n")
    assert src.ok
    assert "const after = 6;" in src.masked


def test_division_after_a_paren_is_not_treated_as_a_regex():
    src = scan("const d = (a + b) / 2 / 3;\nconst after = 7;\n")
    assert src.ok
    assert src.masked.count("/") == 2   # both slashes survive as division
    assert "const after = 7;" in src.masked


def test_regex_is_recognised_after_operators_and_keywords():
    for text in (
        "const r = /ab+/;",
        "f(/ab+/);",
        "const a = [/ab+/];",
        "return /ab+/;",
        "const x = typeof /ab+/;",
        "const y = b ? /ab+/ : c;",
    ):
        src = scan(text)
        assert src.ok, text
        assert "ab+" not in src.masked, text


def test_a_regex_that_would_span_a_newline_is_not_a_regex():
    src = scan("const a = b /\nc;\nconst after = 8;\n")
    assert src.ok
    assert "const after = 8;" in src.masked


def test_jsx_closing_and_self_closing_tags_do_not_open_a_regex():
    src = scan(
        "const el = <div>\n"
        "  <Stat icon={<Coin size=\"12\" color={t.c} />} value={p} />\n"
        "</div>;\n"
        "const after = 9;\n"
    )
    assert src.ok, src.masked
    assert "const after = 9;" in src.masked


def test_shebang_line_is_blanked_and_does_not_lex_as_a_regex():
    src = scan("#!/usr/bin/env node\nconst after = 10;\n")
    assert src.ok
    assert "usr" not in src.masked
    assert "const after = 10;" in src.masked


# ==========================================================================
# degradation: ok=False, never a crash, never a hang
# ==========================================================================
def test_unterminated_block_comment_sets_ok_false():
    src = scan("const a = 1;\n/* never closed\nconst b = 2;\n")
    assert not src.ok
    assert len(src.masked) == len(src.text)


def test_unterminated_template_literal_sets_ok_false():
    assert not scan("const t = `abc ${x} def").ok


def test_unterminated_string_at_eof_sets_ok_false():
    assert not scan('const a = "abc').ok


def test_unbalanced_braces_set_ok_false():
    assert not scan("function f() { return 1;").ok
    assert not scan("} extra").ok


def test_a_newline_inside_a_quote_is_not_a_string_and_damage_stops_at_the_line():
    src = scan("const a = 'oops\nconst b = \"kept\";\nconst after = 11;\n")
    assert src.ok                       # brackets still balance
    assert "oops" in src.masked         # the phantom string was rejected
    assert "kept" not in src.masked     # the real string on the next line is masked
    assert "const after = 11;" in src.masked


def test_empty_and_whitespace_only_sources_are_fine():
    for text in ("", "\n", "   \n\t\n"):
        src = scan(text)
        assert src.ok
        assert src.masked == text
        assert src.trimmed(Span(0, len(text))).is_empty()


def test_pathological_inputs_terminate_and_never_raise():
    for text in (
        "`" * 400,
        "${" * 400,
        "/" * 400,
        "'" * 400,
        "{" * 400 + "}" * 200,
        "/*" * 400,
        "a".join("`${" for _ in range(200)),
        "\x00\x01\ufffd" * 200,
    ):
        src = scan(text)
        assert len(src.masked) == len(src.text)


def test_every_helper_tolerates_a_degraded_source():
    """Checks are required to bail on ok=False, but the helpers must not
    explode if one is called anyway — invariant 3 is 'never raise'."""
    src = scan("function f(a) { g(`x ${ ")
    assert not src.ok
    assert jsparse.find_calls(src, {"g"}) is not None
    assert jsparse.find_constructions(src, {"X"}) is not None
    assert jsparse.collect_imports(src) == []
    assert isinstance(jsparse.collect_bindings(src), dict)
    whole = Span(0, len(src.text))
    assert jsparse.find_functions(src, whole) is not None
    assert jsparse.identifier_uses(src, whole, "a") is not None
    assert jsparse.contains_token(src, whole, {"g"}) in (True, False)
    assert jsparse.parse_object(src, whole) is None
    assert jsparse.function_in_span(src, whole) is None
    assert jsparse.split_args(src, src.masked.index("(")) is not None
    assert jsparse.match_bracket(src, src.masked.rindex("(")) is None
    assert jsparse.parse_params(src, whole)[2] is False


# ==========================================================================
# brackets
# ==========================================================================
def test_match_bracket_handles_nesting_and_mixed_types():
    src = scan("f(a, [b, {c: (d)}], e)")
    i = src.masked.index("(")
    assert jsparse.match_bracket(src, i) == len(src.text) - 1
    assert jsparse.match_bracket(src, src.masked.index("[")) == src.masked.index("]")


def test_match_bracket_returns_none_when_unbalanced_or_not_a_bracket():
    src = scan("f(a, b")
    assert jsparse.match_bracket(src, src.masked.index("(")) is None
    assert jsparse.match_bracket(src, 0) is None
    assert jsparse.match_bracket(src, 9999) is None


def test_split_args_basic_nested_and_trailing_comma():
    src = scan("f(a, g(b, c), [d, e])")
    args, close = jsparse.split_args(src, src.masked.index("("))
    assert close == len(src.text) - 1
    assert [src.raw(src.trimmed(s)) for s in args] == ["a", "g(b, c)", "[d, e]"]

    src2 = scan("f(a, b,)")
    args2, _ = jsparse.split_args(src2, src2.masked.index("("))
    assert len(args2) == 3
    assert src2.trimmed(args2[-1]).is_empty()

    src3 = scan("f()")
    args3, _ = jsparse.split_args(src3, src3.masked.index("("))
    assert args3 == []


def test_split_args_does_not_split_inside_an_arrow_parameter_list():
    src = scan("reg('n', {}, async (a, b) => { h(a, b); })")
    args, _ = jsparse.split_args(src, src.masked.index("("))
    assert len(args) == 3


def test_split_args_tolerates_a_generic_type_argument_containing_a_comma():
    src = scan("reg(name, cfg as Record<string, unknown>, handler)")
    args, _ = jsparse.split_args(src, src.masked.index("("))
    assert [src.raw(src.trimmed(s)) for s in args] == [
        "name", "cfg as Record<string, unknown>", "handler",
    ]


def test_split_args_falls_back_when_angle_brackets_are_comparisons():
    """`a < b, c` has an unbalanced `<`; the split must ignore angles then."""
    src = scan("f(a < b, c)")
    args, _ = jsparse.split_args(src, src.masked.index("("))
    assert len(args) == 2


# ==========================================================================
# calls
# ==========================================================================
def test_find_calls_matches_member_bare_optional_and_generic_forms():
    src = scan(
        "cp.execSync('a');\n"
        "execSync('b');\n"
        "fs.promises.rm('c');\n"
        "maybe?.execSync('d');\n"
        "typed<Opts>('e');\n"
    )
    calls = jsparse.find_calls(src, {"execSync", "rm", "typed"})
    got = [(c.callee, c.method, c.receiver, c.root, c.line) for c in calls]
    assert got == [
        ("cp.execSync", "execSync", "cp", "cp", 1),
        ("execSync", "execSync", "", "execSync", 2),
        ("fs.promises.rm", "rm", "fs.promises", "fs", 3),
        ("maybe.execSync", "execSync", "maybe", "maybe", 4),
        ("typed", "typed", "", "typed", 5),
    ]
    assert all(not c.is_new for c in calls)


def test_find_calls_reports_arg_spans_and_call_span():
    src = scan("cp.execSync(cmd, { shell: true });")
    (call,) = jsparse.find_calls(src, {"execSync"})
    assert [src.raw(src.trimmed(a)) for a in call.args] == ["cmd", "{ shell: true }"]
    assert src.raw(call.args_span) == "cmd, { shell: true }"
    assert src.raw(call.call_span) == "cp.execSync(cmd, { shell: true })"
    assert src.raw(call.name_span) == "cp.execSync"


def test_find_calls_excludes_keywords_and_declarations():
    src = scan(
        "if (rm) { }\n"
        "for (rm of xs) { }\n"
        "while (rm) { }\n"
        "switch (rm) { }\n"
        "function rm(a) { }\n"
        "class rm { }\n"
        "return rm;\n"
    )
    assert jsparse.find_calls(src, {"rm", "if", "for", "while", "switch", "return"}) == []


def test_find_calls_excludes_new_expressions():
    src = scan("const t = new Transport({});")
    assert jsparse.find_calls(src, {"Transport"}) == []


def test_a_call_on_a_non_identifier_receiver_gets_the_unknown_marker():
    """`getFs().rm(p)` and `arr[0].exec(p)` must never look like bare calls;
    a bare call is import-resolvable and these are not."""
    src = scan("getFs().rm(p);\narr[0].exec(q);\n")
    calls = jsparse.find_calls(src, {"rm", "exec"})
    assert [(c.method, c.receiver, c.root) for c in calls] == [
        ("rm", jsparse.UNKNOWN_RECEIVER, jsparse.UNKNOWN_RECEIVER),
        ("exec", jsparse.UNKNOWN_RECEIVER, jsparse.UNKNOWN_RECEIVER),
    ]


def test_find_calls_ignores_matches_inside_strings_and_comments():
    src = scan(
        "const s = 'cp.execSync(evil)';\n"
        "// cp.execSync(evil)\n"
        "const t = `cp.execSync(evil)`;\n"
    )
    assert jsparse.find_calls(src, {"execSync"}) == []


def test_find_calls_honours_the_within_window():
    src = scan("a.rm(1);\nb.rm(2);\n")
    second = src.text.index("b.rm")
    calls = jsparse.find_calls(src, {"rm"}, within=Span(second, len(src.text)))
    assert [c.receiver for c in calls] == ["b"]


def test_find_constructions():
    src = scan(
        "const a = new StreamableHTTPServerTransport({ sessionIdGenerator: g });\n"
        "const b = new sdk.SSEServerTransport('/m', res);\n"
        "const c = new Other();\n"
    )
    cons = jsparse.find_constructions(
        src, {"StreamableHTTPServerTransport", "SSEServerTransport"})
    assert [(c.method, c.is_new, c.line) for c in cons] == [
        ("StreamableHTTPServerTransport", True, 1),
        ("SSEServerTransport", True, 2),
    ]
    assert src.raw(cons[0].call_span).startswith("new StreamableHTTPServerTransport(")
    assert len(cons[1].args) == 2


# ==========================================================================
# functions
# ==========================================================================
def test_function_in_span_parses_every_handler_shape():
    cases = {
        "async ({ path }, extra) => { rm(path); }": ("arrow", True, 2, False),
        "({ path }) => rm(path)": ("arrow", False, 1, True),
        "async function (a, b) { return a; }": ("function", True, 2, False),
        "function named(a) { return a; }": ("function", False, 1, False),
        "x => x + 1": ("arrow", False, 1, True),
        "async x => x": ("arrow", True, 1, True),
        "(a): Promise<void> => { g(a); }": ("arrow", False, 1, False),
        "(a): { ok: boolean } => ({ ok: true })": ("arrow", False, 1, True),
        "((a) => a)": ("arrow", False, 1, True),
        "() => ({ ok: true })": ("arrow", False, 0, True),
    }
    for text, (kind, is_async, count, is_expr) in cases.items():
        src = scan(text)
        fb = jsparse.function_in_span(src, Span(0, len(text)))
        assert fb is not None, text
        assert (fb.kind, fb.is_async, fb.positional_count, fb.body_is_expression) == (
            kind, is_async, count, is_expr), text
        assert fb.params_ok, text


def test_function_in_span_returns_none_for_non_functions():
    for text in ("handlerName", "makeHandler(opts)", "{ a: 1 }", "[1, 2]",
                 "obj.method", "42", ""):
        src = scan(text)
        assert jsparse.function_in_span(src, Span(0, len(text))) is None, text


def test_function_in_span_body_span_is_inside_the_braces():
    text = "async (a) => { doThing(a); }"
    src = scan(text)
    fb = jsparse.function_in_span(src, Span(0, len(text)))
    assert src.raw(fb.body_span).strip() == "doThing(a);"
    assert src.raw(fb.span) == text


def test_find_functions_returns_the_outermost_wrapper_first():
    """mcp-playwright's shape: the real handler is two wrappers deep."""
    text = (
        "wrapHandler('CallTool', wrapWithMonitoring(async (request) => {\n"
        "  return handle(request.params);\n"
        "}))"
    )
    src = scan(text)
    fns = jsparse.find_functions(src, Span(0, len(text)))
    assert len(fns) == 1
    assert [p.name for p in fns[0].params] == ["request"]

    text2 = "wrap(async (outer) => { return (inner) => inner; })"
    src2 = scan(text2)
    fns2 = jsparse.find_functions(src2, Span(0, len(text2)))
    assert [[p.name for p in f.params] for f in fns2] == [["outer"], ["inner"]]
    assert fns2[0].span.start < fns2[1].span.start


def test_find_functions_does_not_mistake_control_flow_for_a_method():
    src = scan("{ if (cond) { a(); } for (const x of xs) { b(); } while (y) { c(); } }")
    assert jsparse.find_functions(src, Span(0, len(src.text))) == []


def test_find_functions_finds_function_declarations_and_expressions():
    text = "const a = function (p) { };\nfunction b(q) { }\nconst c = async (r) => r;\n"
    src = scan(text)
    fns = jsparse.find_functions(src, Span(0, len(text)))
    assert [[p.name for p in f.params] for f in fns] == [["p"], ["q"], ["r"]]


# ==========================================================================
# parameters (design §1.6)
# ==========================================================================
def _params(text: str):
    src = scan(text)
    fb = jsparse.function_in_span(src, Span(0, len(text)))
    assert fb is not None, text
    return fb


def test_plain_and_typed_parameters():
    fb = _params("(a, b: string, c: Record<string, unknown>) => a")
    assert fb.params_ok
    assert fb.positional_count == 3
    assert [(p.name, p.index, p.type_text) for p in fb.params] == [
        ("a", 0, ""), ("b", 1, "string"), ("c", 2, "Record<string, unknown>"),
    ]


def test_default_values_are_stripped_before_the_type():
    fb = _params("(a: number = 3, cb = () => {}) => a")
    assert fb.params_ok
    assert [(p.name, p.type_text) for p in fb.params] == [("a", "number"), ("cb", "")]
    assert fb.positional_count == 2


def test_object_destructuring_flattens_to_one_param_per_binding():
    fb = _params("({ id: orgId, path, depth = 2 }, extra) => orgId")
    assert fb.params_ok
    assert [(p.name, p.source_name, p.index, p.is_destructured) for p in fb.params] == [
        ("orgId", "id", 0, True),
        ("path", "path", 0, True),
        ("depth", "depth", 0, True),
        ("extra", "extra", 1, False),
    ]
    assert fb.positional_count == 2
    assert [p.name for p in fb.param_at(0)] == ["orgId", "path", "depth"]
    assert [p.name for p in fb.param_at(1)] == ["extra"]


def test_destructuring_with_a_type_annotation_and_a_default():
    fb = _params("({ path }: Args = {}) => path")
    assert fb.params_ok
    assert [(p.name, p.index) for p in fb.params] == [("path", 0)]


def test_rest_parameters():
    fb = _params("(first, ...rest) => first")
    assert fb.params_ok
    assert [(p.name, p.is_rest, p.index) for p in fb.params] == [
        ("first", False, 0), ("rest", True, 1),
    ]

    fb2 = _params("({ a, ...others }) => a")
    assert fb2.params_ok
    assert [(p.name, p.is_rest) for p in fb2.params] == [("a", False), ("others", True)]


def test_nested_and_array_patterns_are_a_hard_suppress():
    """§1.6 rules 4/5: anything we cannot flatten sets params_ok=False, and
    every check treats that as 'do not analyse this handler'."""
    for text in (
        "({ a: { b } }) => b",
        "([a, b]) => a",
        "({ [key]: v }) => v",
        "(a, [b]) => a",
    ):
        fb = _params(text)
        assert not fb.params_ok, text


def test_zero_parameters():
    fb = _params("async () => ({ ok: true })")
    assert fb.params_ok
    assert fb.positional_count == 0
    assert fb.params == ()


def test_any_typed_parameter_exposes_its_type_text():
    fb = _params("async (args: any, extra: any) => args")
    assert [p.type_text for p in fb.params] == ["any", "any"]


def test_trailing_comma_in_a_parameter_list_is_not_a_parameter():
    fb = _params("(a, b,) => a")
    assert fb.params_ok
    assert fb.positional_count == 2


# ==========================================================================
# objects
# ==========================================================================
def test_parse_object_entries():
    text = (
        "{ title: 'Run', inputSchema: { cmd: z.string() }, 'quoted-key': 1,\n"
        "  shorthand, [computed]: 2, async handler(a, b) { g(a); }, ...rest }"
    )
    src = scan(text)
    obj = jsparse.parse_object(src, Span(0, len(text)))
    assert obj is not None and obj.ok
    assert obj.has_spread
    keys = [e.key for e in obj.entries]
    assert keys == ["title", "inputSchema", "quoted-key", "shorthand", "", "handler", ""]
    assert obj.get("inputSchema") is not None
    assert src.raw(obj.get("inputSchema").value_span) == "{ cmd: z.string() }"
    assert obj.get("shorthand").is_shorthand
    assert obj.get("shorthand").value_span.is_empty()
    assert obj.get("handler").is_method
    assert obj.get("") is not None  # computed key, first match


def test_parse_object_method_value_span_parses_as_a_function():
    text = "{ async handler(a, b) { g(a); } }"
    src = scan(text)
    obj = jsparse.parse_object(src, Span(0, len(text)))
    entry = obj.get("handler")
    fb = jsparse.function_in_span(src, entry.value_span)
    assert fb is not None and fb.kind == "method"
    assert [p.name for p in fb.params] == ["a", "b"]


def test_parse_object_returns_none_for_non_objects():
    for text in ("[1, 2]", "fn(a)", "'str'", "identifier", "{ a: 1 } + 1"):
        src = scan(text)
        assert jsparse.parse_object(src, Span(0, len(text))) is None, text


def test_parse_object_line_numbers_are_per_entry():
    text = "{\n  a: 1,\n  b: 2,\n}"
    src = scan(text)
    obj = jsparse.parse_object(src, Span(0, len(text)))
    assert [(e.key, e.line) for e in obj.entries] == [("a", 2), ("b", 3)]


def test_parse_object_ignores_commas_inside_nested_structures():
    text = "{ a: [1, 2], b: f(3, 4), c: `x,y`, d: 'p,q' }"
    src = scan(text)
    obj = jsparse.parse_object(src, Span(0, len(text)))
    assert [e.key for e in obj.entries] == ["a", "b", "c", "d"]


def test_string_literal_value():
    src = scan("f('run', \"walk\", `crawl`, `hole ${x}`, name)")
    args, _ = jsparse.split_args(src, src.masked.index("("))
    vals = [jsparse.string_literal_value(src, a) for a in args]
    assert vals == ["run", "walk", "crawl", None, None]


# ==========================================================================
# module structure
# ==========================================================================
def test_collect_imports_covers_every_esm_and_cjs_form():
    text = (
        "import { z } from 'zod';\n"
        "import path from 'node:path';\n"
        "import * as cp from 'node:child_process';\n"
        "import fse, { remove as rmrf } from 'fs-extra';\n"
        "import type { Tool } from '@modelcontextprotocol/sdk/types.js';\n"
        "import { type Cfg, other } from './cfg.js';\n"
        "import './side-effect.js';\n"
        "const legacy = require('child_process');\n"
        "const { execSync, spawn: sp } = require('node:child_process');\n"
    )
    src = scan(text)
    recs = {(r.module, r.local, r.imported, r.is_type_only)
            for r in jsparse.collect_imports(src)}
    assert ("zod", "z", "z", False) in recs
    assert ("node:path", "path", "default", False) in recs
    assert ("node:child_process", "cp", "*", False) in recs
    assert ("fs-extra", "fse", "default", False) in recs
    assert ("fs-extra", "rmrf", "remove", False) in recs
    assert ("@modelcontextprotocol/sdk/types.js", "Tool", "Tool", True) in recs
    assert ("./cfg.js", "Cfg", "Cfg", True) in recs
    assert ("./cfg.js", "other", "other", False) in recs
    assert ("./side-effect.js", "", "", False) in recs
    assert ("child_process", "legacy", "*", False) in recs
    assert ("node:child_process", "execSync", "execSync", False) in recs
    assert ("node:child_process", "sp", "spawn", False) in recs


def test_collect_imports_ignores_dynamic_import_and_commented_imports():
    src = scan(
        "// import { evil } from 'evil';\n"
        "const m = await import('dynamic');\n"
        "const s = \"import x from 'fake'\";\n"
    )
    assert [r.module for r in jsparse.collect_imports(src)] == []


def test_collect_imports_output_is_deterministic():
    text = "import b from 'b';\nimport a from 'a';\n"
    src = scan(text)
    assert jsparse.collect_imports(src) == jsparse.collect_imports(src)


def test_collect_bindings_is_top_level_only_and_first_wins():
    text = (
        "const A = { a: 1 };\n"
        "let B = 'x';\n"
        "var C = 2;\n"
        "function D(p) { const A = 'shadow'; }\n"
        "class E { }\n"
        "const A = 'later';\n"
        "function inner() { const HIDDEN = 1; }\n"
    )
    src = scan(text)
    b = jsparse.collect_bindings(src)
    assert set(b) == {"A", "B", "C", "D", "E", "inner"}
    assert b["A"].kind == "const"
    assert src.raw(b["A"].value_span) == "{ a: 1 }"    # first declaration wins
    assert b["B"].kind == "let" and b["C"].kind == "var"
    assert b["D"].kind == "function"
    assert "HIDDEN" not in b


def test_collect_bindings_handles_a_missing_semicolon():
    src = scan("const A = { a: 1 }\nconst B = 2\n")
    b = jsparse.collect_bindings(src)
    assert src.raw(b["A"].value_span) == "{ a: 1 }"
    assert src.raw(b["B"].value_span) == "2"


def test_collect_bindings_keeps_a_multiline_initializer_whole():
    src = scan("const H = async (args) => {\n  rm(args.path);\n};\nconst I = 1;\n")
    b = jsparse.collect_bindings(src)
    fb = jsparse.function_in_span(src, b["H"].value_span)
    assert fb is not None and [p.name for p in fb.params] == ["args"]


def test_resolve_span_follows_hops_and_gives_up_safely():
    src = scan("const A = B;\nconst B = { k: 1 };\nconst C = D;\nconst X = Y;\nconst Y = X;\n")
    b = jsparse.collect_bindings(src)
    resolved = jsparse.resolve_span(src, "A", b)
    assert resolved is not None and src.raw(resolved) == "{ k: 1 }"
    assert jsparse.resolve_span(src, "C", b) is None      # D is undeclared
    assert jsparse.resolve_span(src, "X", b) is None      # cycle
    assert jsparse.resolve_span(src, "nope", b) is None


def test_resolve_span_respects_the_depth_limit():
    src = scan("const A = B;\nconst B = C;\nconst C = D;\nconst D = { deep: 1 };\n")
    b = jsparse.collect_bindings(src)
    assert jsparse.resolve_span(src, "A", b, depth=1) is None
    assert jsparse.resolve_span(src, "A", b, depth=3) is not None


# ==========================================================================
# identifiers
# ==========================================================================
def test_identifier_uses_excludes_property_and_object_key_position():
    text = "fs.rm(args.path); const o = { path: BASE, args: 1 }; use(path); cfg.args;"
    src = scan(text)
    whole = Span(0, len(text))
    path_uses = jsparse.identifier_uses(src, whole, "path")
    assert len(path_uses) == 1                       # only `use(path)`
    assert src.text[path_uses[0]:path_uses[0] + 4] == "path"
    assert text[:path_uses[0]].endswith("use(")
    args_uses = jsparse.identifier_uses(src, whole, "args")
    assert len(args_uses) == 1                       # only `args.path`
    assert text[:args_uses[0]].endswith("rm(")


def test_identifier_uses_is_word_bounded_and_ignores_strings():
    text = "const pathname = 1; const p = 'path'; take(path);"
    src = scan(text)
    uses = jsparse.identifier_uses(src, Span(0, len(text)), "path")
    assert len(uses) == 1
    assert text[:uses[0]].endswith("take(")


def test_identifier_uses_counts_a_property_read_on_a_tainted_root():
    """`args.path` IS a use of `args` — the dominant real taint shape."""
    text = "rm(args.path)"
    src = scan(text)
    assert len(jsparse.identifier_uses(src, Span(0, len(text)), "args")) == 1


def test_identifier_uses_skips_optional_chaining_property_position():
    text = "const v = cfg?.path; go(path);"
    src = scan(text)
    assert len(jsparse.identifier_uses(src, Span(0, len(text)), "path")) == 1


def test_contains_token_matches_identifiers_and_members():
    text = "if (ALLOWED.includes(cmd)) { await validatePath(p); }"
    src = scan(text)
    whole = Span(0, len(text))
    assert jsparse.contains_token(src, whole, {"includes"})
    assert jsparse.contains_token(src, whole, {"validatePath"})
    assert jsparse.contains_token(src, whole, {"ALLOWED"})
    assert not jsparse.contains_token(src, whole, {"resolve"})
    assert not jsparse.contains_token(src, whole, {"include"})   # word-bounded
    assert not jsparse.contains_token(src, whole, set())


def test_contains_token_ignores_comments_and_strings():
    src = scan("// validatePath(p)\nconst s = 'sanitize';\nrun(x);")
    whole = Span(0, len(src.text))
    assert not jsparse.contains_token(src, whole, {"validatePath", "sanitize"})


# ==========================================================================
# file discovery (design §2)
# ==========================================================================
def _touch(p: Path, body: str = "const a = 1;\n") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_iter_source_files_extensions_and_directory_pruning(tmp_path):
    for rel in (
        "src/index.ts", "src/app.tsx", "src/m.mts", "src/c.cts",
        "src/a.js", "src/b.jsx", "src/d.mjs", "src/e.cjs",
        "scripts/start-server.ts",          # explicitly NOT skipped
        "lib/util.ts", "app/page.ts",       # generic words must not be skipped
        "src/types.d.ts",
        "src/bundle.min.js", "src/x.bundle.js",
        "src/index.test.ts", "src/index.spec.ts",
        "README.md", "package.json",
        "node_modules/pkg/index.js",
        "dist/index.js", "build/index.js", "out/index.js", "coverage/i.js",
        ".next/i.js", ".git/i.js", "vendor/i.js", "bower_components/i.js",
        "tests/thing.ts", "test/thing.ts", "__tests__/t.ts", "e2e/t.ts",
        "examples/demo.ts", "example/demo.ts", "demo/x.ts", "fixtures/f.ts",
        "benchmark/b.ts", "evals/e.ts", "__mocks__/m.ts",
    ):
        _touch(tmp_path / rel)

    found = sorted(p.relative_to(tmp_path).as_posix()
                   for p in jsparse.iter_source_files(tmp_path))
    assert found == [
        "app/page.ts",
        "lib/util.ts",
        "scripts/start-server.ts",
        "src/a.js", "src/app.tsx", "src/b.jsx", "src/c.cts", "src/d.mjs",
        "src/e.cjs", "src/index.ts", "src/m.mts",
    ]


def test_iter_source_files_prunes_relative_to_root_not_absolute_path(tmp_path):
    """The skip set contains 'tests' and 'fixtures'. A check run against a
    fixture directory that itself lives under tests/fixtures must still see
    its files, or every check's own test suite passes vacuously."""
    root = tmp_path / "tests" / "fixtures" / "ts_noise_common"
    _touch(root / "server.ts")
    _touch(root / "sub" / "lowlevel.ts")
    found = sorted(p.name for p in jsparse.iter_source_files(root))
    assert found == ["lowlevel.ts", "server.ts"]


def test_iter_source_files_is_deterministic(tmp_path):
    for rel in ("b.ts", "a.ts", "z/y.ts", "z/a.ts", "c/b.ts"):
        _touch(tmp_path / rel)
    first = list(jsparse.iter_source_files(tmp_path))
    assert first == list(jsparse.iter_source_files(tmp_path))
    assert [p.name for p in first] == ["a.ts", "b.ts", "b.ts", "a.ts", "y.ts"]


def test_iter_source_files_on_a_missing_or_empty_root(tmp_path):
    assert list(jsparse.iter_source_files(tmp_path / "nope")) == []
    (tmp_path / "empty").mkdir()
    assert list(jsparse.iter_source_files(tmp_path / "empty")) == []


def test_load_reads_and_lexes(tmp_path):
    p = tmp_path / "a.ts"
    _touch(p, "const s = 'hi';\n")
    src = jsparse.load(p)
    assert src is not None and src.ok
    assert src.path == p
    assert "hi" not in src.masked


def test_load_returns_none_for_missing_oversized_and_minified_files(tmp_path):
    assert jsparse.load(tmp_path / "missing.ts") is None

    big = tmp_path / "big.js"
    big.write_text("x\n" * 2000, encoding="utf-8")
    assert jsparse.load(big, max_bytes=100) is None

    minified = tmp_path / "m.js"
    minified.write_text("var a=1;" * 500 + "\n", encoding="utf-8")
    assert jsparse.load(minified) is None


def test_load_never_raises_on_undecodable_or_binary_content(tmp_path):
    latin = tmp_path / "latin.js"
    latin.write_bytes(b"const caf\xe9 = 'na\xefve';\n")
    src = jsparse.load(latin)
    assert src is not None
    assert len(src.masked) == len(src.text)

    binary = tmp_path / "bin.js"
    binary.write_bytes(bytes(range(256)) * 4)
    binary_src = jsparse.load(binary)
    assert binary_src is None or len(binary_src.masked) == len(binary_src.text)

    empty = tmp_path / "empty.js"
    empty.write_bytes(b"")
    src2 = jsparse.load(empty)
    assert src2 is not None and src2.ok and src2.masked == ""


def test_load_of_a_directory_returns_none(tmp_path):
    d = tmp_path / "dir.ts"
    d.mkdir()
    assert jsparse.load(d) is None


# ==========================================================================
# end-to-end: the registration shapes the checks depend on
# ==========================================================================
_SERVER = """\
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import * as cp from "node:child_process";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.registerTool(
  "run",
  { title: "Run", inputSchema: { cmd: z.string() } },
  async ({ cmd }, extra) => {
    return cp.execSync(`git ${cmd}`);
  },
);

server.tool("ping", "no input at all", async (extra) => ({ ok: true }));

server.server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  switch (name) {
    case "purge":
      return del(args.target);
  }
});
"""


def test_end_to_end_registration_extraction():
    src = scan(_SERVER, Path("server.ts"))
    assert src.ok

    modules = {r.module for r in jsparse.collect_imports(src)}
    assert "@modelcontextprotocol/sdk/server/mcp.js" in modules
    assert "node:child_process" in modules

    reg = jsparse.find_calls(src, {"registerTool"})
    assert len(reg) == 1
    call = reg[0]
    assert call.receiver == "server"
    # trailing comma => trailing empty span, which callers strip (rule R1)
    assert len(call.args) == 4 and src.trimmed(call.args[-1]).is_empty()

    cfg = jsparse.parse_object(src, call.args[1])
    assert cfg is not None and cfg.ok and cfg.get("inputSchema") is not None

    fb = jsparse.function_in_span(src, call.args[-2])
    assert fb is not None and fb.params_ok and fb.is_async
    assert [p.name for p in fb.param_at(0)] == ["cmd"]
    assert [p.name for p in fb.param_at(1)] == ["extra"]

    sinks = jsparse.find_calls(src, {"execSync"}, within=fb.body_span)
    assert len(sinks) == 1 and sinks[0].receiver == "cp"
    assert jsparse.identifier_uses(src, sinks[0].args[0], "cmd") == [
        src.text.index("${cmd}") + 2
    ]


def test_end_to_end_schemaless_tool_has_no_input_bindings():
    """RECON A rule R2: `tool(name, description, cb)` has no schema, so the
    callback's parameter 0 is the server context, not tool arguments."""
    src = scan(_SERVER, Path("server.ts"))
    (call,) = [c for c in jsparse.find_calls(src, {"tool"}) if c.receiver == "server"]
    assert len(call.args) == 3
    assert jsparse.parse_object(src, call.args[1]) is None   # a description, not a config
    fb = jsparse.function_in_span(src, call.args[-1])
    assert fb is not None and [p.name for p in fb.params] == ["extra"]


def test_end_to_end_lowlevel_handler():
    src = scan(_SERVER, Path("server.ts"))
    (call,) = jsparse.find_calls(src, {"setRequestHandler"})
    assert call.receiver == "server.server"
    assert src.raw(src.trimmed(call.args[0])) == "CallToolRequestSchema"
    fns = jsparse.find_functions(src, call.args[1])
    assert fns and [p.name for p in fns[0].params] == ["request"]
    body = fns[0].body_span
    assert jsparse.contains_token(src, body, {"params"})
    assert jsparse.identifier_uses(src, body, "request")


def test_end_to_end_line_numbers_point_at_editable_lines():
    src = scan(_SERVER, Path("server.ts"))
    lines = _SERVER.split("\n")
    (call,) = jsparse.find_calls(src, {"registerTool"})
    assert "server.registerTool(" in lines[call.line - 1]
    (sink,) = jsparse.find_calls(src, {"execSync"})
    assert "cp.execSync(" in lines[sink.line - 1]
