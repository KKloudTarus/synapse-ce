#!/usr/bin/env python3
"""Fail-closed syntactic rejection proof for blinded Java SAST proposals.

The gate is deliberately narrower than a Java parser.  A rejection is safe only
when the supplied context uses the small, fully checked grammar below; every
other input returns a confirmation-preserving rejection of the proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


_HEADER = re.compile(r"^// synapse-sast-proof-context: start_line=([1-9][0-9]*)\r?\n")
_UNSUPPORTED_CONTROL = {"for", "while", "switch", "try", "catch", "finally", "do", "synchronized", "else", "throw"}
_SINKS = {
    "CWE-79": {"print", "println", "write"},
    "CWE-89": {"execute", "executeQuery", "executeUpdate", "executeBatch"},
    "CWE-78": {"exec", "start"},
}


@dataclass(frozen=True)
class _Token:
    value: str
    line: int
    kind: str


class _Unproven(ValueError):
    pass


def _lex(source: str, start_line: int) -> list[_Token]:
    """Tokenize a deliberately small Java subset and reject uncertain syntax."""
    tokens: list[_Token] = []
    index = 0
    line = start_line
    length = len(source)
    while index < length:
        char = source[index]
        if char in " \t\r":
            index += 1
            continue
        if char == "\n":
            line += 1
            index += 1
            continue
        if source.startswith("//", index) or source.startswith("/*", index):
            raise _Unproven("comments are outside the proof grammar")
        if char in {'"', "'"}:
            quote = char
            index += 1
            literal: list[str] = []
            while index < length:
                current = source[index]
                if current == "\n":
                    raise _Unproven("unterminated literal")
                if current == "\\":
                    if index + 1 >= length:
                        raise _Unproven("unterminated escape")
                    literal.append(source[index : index + 2])
                    index += 2
                    continue
                if current == quote:
                    index += 1
                    break
                literal.append(current)
                index += 1
            else:
                raise _Unproven("unterminated literal")
            if "{" in "".join(literal) or "}" in "".join(literal):
                raise _Unproven("braces inside literals are outside the proof grammar")
            tokens.append(_Token("<literal>", line, "literal"))
            continue
        if char.isalpha() or char in "_$":
            end = index + 1
            while end < length and (source[end].isalnum() or source[end] in "_$"):
                end += 1
            tokens.append(_Token(source[index:end], line, "identifier"))
            index = end
            continue
        if char.isdigit():
            end = index + 1
            while end < length and source[end].isdigit():
                end += 1
            tokens.append(_Token(source[index:end], line, "number"))
            index = end
            continue
        if char in "{}();.,=![]":
            tokens.append(_Token(char, line, "symbol"))
            index += 1
            continue
        raise _Unproven("unsupported Java token")
    return tokens


def _matching_brace(tokens: list[_Token], opening: int) -> int:
    depth = 0
    for index in range(opening, len(tokens)):
        if tokens[index].value == "{":
            depth += 1
        elif tokens[index].value == "}":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                break
    raise _Unproven("unbalanced braces")


def _sink_calls(tokens: list[_Token], sink_names: set[str]) -> list[_Token]:
    return [token for index, token in enumerate(tokens[:-1]) if token.kind == "identifier" and token.value in sink_names and tokens[index + 1].value == "("]


def _method_calls(tokens: list[_Token]) -> list[_Token]:
    """Return every syntactically apparent invocation in the proof subset.

    Findings identify a source line rather than a sink expression.  Treating an
    unfamiliar call as harmless would let it share a line with the claimed sink
    and make the identity of that finding unknowable.
    """
    return [token for index, token in enumerate(tokens[:-1]) if token.kind == "identifier" and token.value not in {"if"} and tokens[index + 1].value == "("]


def _validate_method(tokens: list[_Token], sink_names: set[str], finding_line: int) -> None:
    if not tokens:
        raise _Unproven("empty context")
    try:
        method_open = next(index for index, token in enumerate(tokens) if token.value == "{")
    except StopIteration as err:
        raise _Unproven("method body is missing") from err
    method_close = _matching_brace(tokens, method_open)
    if method_close != len(tokens) - 1:
        raise _Unproven("context does not contain exactly one complete method")
    signature = tokens[:method_open]
    if not signature or signature[-1].value != ")" or any(token.value in {";", "="} for token in signature):
        raise _Unproven("method signature is outside the proof grammar")
    body = tokens[method_open + 1 : method_close]
    if any(token.value in _UNSUPPORTED_CONTROL for token in body):
        raise _Unproven("control flow is outside the proof grammar")
    if any(token.value == "=" for token in body):
        raise _Unproven("assignment is outside the proof grammar")
    if any(token.value == "this" for token in body):
        raise _Unproven("field access is outside the proof grammar")

    false_branch_sinks: list[_Token] = []
    false_branch_calls: list[_Token] = []
    index = 0
    while index < len(body):
        token = body[index]
        if token.value != "if":
            if token.value in {"{", "}"}:
                raise _Unproven("nested braces are outside the proof grammar")
            index += 1
            continue
        if index + 4 >= len(body) or [item.value for item in body[index + 1 : index + 5]] != ["(", "false", ")", "{"]:
            raise _Unproven("only literal if (false) branches are supported")
        branch_open = index + 4
        branch_close = _matching_brace(body, branch_open)
        branch = body[branch_open + 1 : branch_close]
        if not branch or any(item.value in {"{", "}", "if"} | _UNSUPPORTED_CONTROL for item in branch):
            raise _Unproven("nested branch content is outside the proof grammar")
        if branch[-1].value != ";":
            raise _Unproven("literal-false branch must contain one complete statement")
        if sum(1 for item in branch if item.value == ";") != 1:
            raise _Unproven("literal-false branch contains multiple statements")
        false_branch_sinks.extend(_sink_calls(branch, sink_names))
        false_branch_calls.extend(_method_calls(branch))
        index = branch_close + 1

    all_sinks = _sink_calls(body, sink_names)
    all_calls = _method_calls(body)
    if not false_branch_sinks or len(false_branch_sinks) != len(all_sinks):
        raise _Unproven("a potentially matching sink is reachable or ambiguous")
    if len(false_branch_calls) != len(all_calls):
        raise _Unproven("a method invocation is reachable or ambiguous")
    matching_line = [sink for sink in false_branch_sinks if sink.line == finding_line]
    calls_on_finding_line = [call for call in all_calls if call.line == finding_line]
    if len(matching_line) != 1 or len(calls_on_finding_line) != 1:
        raise _Unproven("finding line does not identify exactly one unreachable sink")


def prove_rejection(proposal: dict[str, Any]) -> tuple[bool, str]:
    """Return whether a literal-false Java sink proof permits a SAST rejection.

    Invalid inputs always return ``False``.  The reason is intentionally short so
    callers can retain it without treating untrusted source as instructions.
    """
    try:
        if not isinstance(proposal, dict) or set(proposal) != {"id", "finding", "source_context"}:
            raise _Unproven("proposal shape is invalid")
        finding = proposal["finding"]
        if not isinstance(finding, dict) or set(finding) != {"file", "line", "cwe"}:
            raise _Unproven("finding shape is invalid")
        if not isinstance(proposal["id"], str) or not isinstance(finding["file"], str) or not isinstance(finding["line"], int) or isinstance(finding["line"], bool) or not isinstance(finding["cwe"], str) or not isinstance(proposal["source_context"], str):
            raise _Unproven("proposal fields are invalid")
        sink_names = _SINKS.get(finding["cwe"])
        if sink_names is None:
            raise _Unproven("CWE is not supported by the proof gate")
        match = _HEADER.match(proposal["source_context"])
        if match is None:
            raise _Unproven("source context has no unambiguous line header")
        if "\\u" in proposal["source_context"][match.end() :]:
            raise _Unproven("Java Unicode escapes are outside the proof grammar")
        start_line = int(match.group(1))
        _validate_method(_lex(proposal["source_context"][match.end() :], start_line), sink_names, finding["line"])
    except _Unproven as error:
        return False, str(error)
    return True, "all potentially matching sinks are in literal if (false) bodies"
