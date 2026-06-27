"""tool_input_validation — flag loosely-typed parameters on `@mcp.tool()` functions.

Background: FastMCP exposes a tool's parameter schema to the LLM as part of
the protocol handshake. A parameter typed as bare `str` (with no length cap)
or `Any` (with no shape constraint) lets the model emit oversized or
unexpected payloads, which is the substrate most prompt-injection-via-tool-
description attacks rely on. Constraining the schema closes the window
without losing useful expressiveness.

This is a LOW-severity hygiene check, not a CVE detector. It will produce
findings on most well-written FastMCP servers — even Anthropic's reference
implementations take bare `str` parameters in places. Read the output as
"here are the spots where input validation could be tightened," not as
"these are exploitable."

Patterns flagged (per @mcp.tool() decorated function, per parameter):

  UNTYPED         parameter with no annotation at all
  LOOSE_STR       parameter annotated `str` with no Field(...) / Length / pattern
  LOOSE_BYTES     parameter annotated `bytes` with no constraint
  LOOSE_ANY       parameter annotated `Any` / `typing.Any`
  LOOSE_COLLECTION parameter annotated `list[Any]`, `dict[str, Any]`, `tuple[Any, ...]`

Patterns NOT flagged:

  - `int`, `float`, `bool`, `bytes` with `Annotated[..., Field(max_length=...)]`
  - `Literal[...]` (explicit allow-list)
  - Pydantic models / dataclasses (carry their own validation)
  - Annotated[str, Field(max_length=N)] / Annotated[str, Field(pattern=...)]
  - `pathlib.Path`, custom NewType — assumed to be intentional
"""
from __future__ import annotations

import ast
from pathlib import Path

from mcp_audit.finding import Finding, Severity

CHECK_ID = "tool_input_validation"

_SKIP_DIRS = {
    ".venv", "venv", "env", "node_modules", ".git", "site-packages",
    ".tox", ".nox", "build", "dist", "__pycache__",
}

# Names that, when present inside `Annotated[T, ...]`, count as a real
# constraint (any of these is enough to suppress the finding).
_CONSTRAINT_CALL_NAMES = {
    "Field",        # pydantic.Field(max_length=...) etc.
    "constr",       # pydantic v1 constrained str factory
    "conint",
    "conlist",
    "Length",       # annotated-types
    "Le", "Lt", "Ge", "Gt", "MinLen", "MaxLen",
    "Pattern", "Predicate", "Interval",
}


def _should_skip(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _is_mcp_tool_decorator(decorator: ast.expr) -> bool:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(target, ast.Attribute) and target.attr == "tool"


def _is_constraint_call(node: ast.expr) -> bool:
    """True if `node` is a call to a known constraint factory (Field(...),
    Length(...), constr(...), etc.) — the signal that an Annotated[...]
    actually constrains the type."""
    if not isinstance(node, ast.Call):
        return False
    fn = node.func
    if isinstance(fn, ast.Name) and fn.id in _CONSTRAINT_CALL_NAMES:
        return True
    if isinstance(fn, ast.Attribute) and fn.attr in _CONSTRAINT_CALL_NAMES:
        return True
    return False


def _annotated_inner(ann: ast.expr) -> list[ast.expr] | None:
    """If `ann` is `Annotated[T, m1, m2, ...]`, return [T, m1, m2, ...];
    otherwise None. Handles both `Annotated[T, m]` and `typing.Annotated[T, m]`."""
    if not isinstance(ann, ast.Subscript):
        return None
    value = ann.value
    is_annotated = (
        (isinstance(value, ast.Name) and value.id == "Annotated")
        or (isinstance(value, ast.Attribute) and value.attr == "Annotated")
    )
    if not is_annotated:
        return None
    slice_node = ann.slice
    if isinstance(slice_node, ast.Tuple):
        return list(slice_node.elts)
    return [slice_node]


def _looseness(ann: ast.expr | None) -> tuple[str, str] | None:
    """Classify the annotation. Return (kind, type_name) if loose, else None."""
    if ann is None:
        return ("UNTYPED", "")

    inner = _annotated_inner(ann)
    if inner is not None:
        # Annotated[T, m1, m2, ...]. If any metadata is a constraint call,
        # the parameter is constrained — clean.
        for meta in inner[1:]:
            if _is_constraint_call(meta):
                return None
        # No constraint metadata — fall through and judge the base T as if bare.
        base = inner[0] if inner else None
        return _looseness(base)

    if isinstance(ann, ast.Name):
        if ann.id == "str":
            return ("LOOSE_STR", "str")
        if ann.id == "bytes":
            return ("LOOSE_BYTES", "bytes")
        if ann.id == "Any":
            return ("LOOSE_ANY", "Any")
        return None

    if isinstance(ann, ast.Attribute) and ann.attr == "Any":
        # typing.Any
        return ("LOOSE_ANY", "Any")

    if isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name):
        container = ann.value.id
        slice_node = ann.slice
        inner_args = (
            slice_node.elts if isinstance(slice_node, ast.Tuple) else [slice_node]
        )
        if container in {"list", "List", "tuple", "Tuple", "set", "Set", "frozenset"}:
            if any(_is_any(a) for a in inner_args):
                return ("LOOSE_COLLECTION", f"{container}[Any]")
        if container in {"dict", "Dict", "Mapping", "MutableMapping"}:
            if any(_is_any(a) for a in inner_args):
                return ("LOOSE_COLLECTION", f"{container}[..., Any]")

    return None


def _is_any(node: ast.expr) -> bool:
    if isinstance(node, ast.Name) and node.id == "Any":
        return True
    if isinstance(node, ast.Attribute) and node.attr == "Any":
        return True
    return False


def _check_file(path: Path) -> list[Finding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_is_mcp_tool_decorator(d) for d in node.decorator_list):
            continue

        all_args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
        for arg in all_args:
            if arg.arg in ("self", "cls"):
                continue
            looseness = _looseness(arg.annotation)
            if looseness is None:
                continue
            kind, type_name = looseness

            kind_text = {
                "UNTYPED": "is unannotated",
                "LOOSE_STR": "is annotated `str` with no Field / Length / pattern constraint",
                "LOOSE_BYTES": "is annotated `bytes` with no constraint",
                "LOOSE_ANY": "is annotated `Any`",
                "LOOSE_COLLECTION": f"is annotated `{type_name}` (open-ended collection)",
            }[kind]

            findings.append(
                Finding(
                    check=CHECK_ID,
                    severity=Severity.LOW,
                    path=path,
                    line=arg.lineno,
                    message=(
                        f"tool '{node.name}' parameter '{arg.arg}' {kind_text}. "
                        "FastMCP exposes the tool's parameter schema to the LLM, and a parameter "
                        "without explicit constraints lets a model emit oversized or unexpected "
                        "payloads. Most prompt-injection-via-tool-description attacks rely on "
                        "large free-form string fields; constraining the schema closes that window "
                        "without losing useful expressiveness."
                    ),
                    remediation=(
                        "Replace the bare type with an Annotated[...] form: "
                        "`Annotated[str, Field(max_length=256)]` for free-form strings, "
                        "`Literal['a','b','c']` for enum-shaped params, or a Pydantic model / "
                        "dataclass for structured input. For `Any` / `dict[str, Any]` / `list[Any]` "
                        "parameters, model the shape explicitly. If the looseness is intentional "
                        "(e.g. truly arbitrary user prose), document it in the tool's docstring so "
                        "reviewers know it's a deliberate choice."
                    ),
                )
            )
    return findings


def check(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for py in root.rglob("*.py"):
        if _should_skip(py):
            continue
        findings.extend(_check_file(py))
    return findings
