from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class CallSite:
    name: str
    line: int
    args_repr: List[str]
    assigns_to: List[str] = field(default_factory=list)


@dataclass
class FunctionInfo:
    name: str
    start_line: int
    end_line: int
    params: List[str]
    calls: List[CallSite] = field(default_factory=list)
    assignments: Dict[str, str] = field(default_factory=dict)


@dataclass
class ParsedModule:
    path: str
    code: str
    tree: ast.AST
    functions: Dict[str, FunctionInfo]
    lines: List[str]

    def get_line(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].rstrip("\n")
        return ""

    def find_function_by_line(self, line: int) -> Optional[FunctionInfo]:
        for fn in self.functions.values():
            if fn.start_line <= line <= fn.end_line:
                return fn
        return None


class _Analyzer(ast.NodeVisitor):
    def __init__(self, source: str):
        self.source = source
        self.functions: Dict[str, FunctionInfo] = {}
        self.current_function: Optional[FunctionInfo] = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        params = [arg.arg for arg in node.args.args]
        end_line = getattr(node, "end_lineno", node.lineno)
        fn = FunctionInfo(name=node.name, start_line=node.lineno, end_line=end_line, params=params)
        self.functions[node.name] = fn
        previous = self.current_function
        self.current_function = fn
        self.generic_visit(node)
        self.current_function = previous

    def visit_Assign(self, node: ast.Assign) -> None:
        if not self.current_function:
            return
        value_repr = ast.get_source_segment(self.source, node.value) or ast.dump(node.value)
        targets: List[str] = []
        for t in node.targets:
            if isinstance(t, ast.Name):
                targets.append(t.id)
                self.current_function.assignments[t.id] = value_repr
        if isinstance(node.value, ast.Call):
            call_name = self._call_name(node.value)
            self.current_function.calls.append(
                CallSite(
                    name=call_name,
                    line=node.lineno,
                    args_repr=[ast.get_source_segment(self.source, arg) or ast.dump(arg) for arg in node.value.args],
                    assigns_to=targets,
                )
            )
            return
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self.current_function:
            self.current_function.calls.append(
                CallSite(
                    name=self._call_name(node),
                    line=node.lineno,
                    args_repr=[ast.get_source_segment(self.source, arg) or ast.dump(arg) for arg in node.args],
                )
            )
        self.generic_visit(node)

    def _call_name(self, node: ast.Call) -> str:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts = []
            current = func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ast.dump(func)


def parse_python_module(path: str, code: str) -> ParsedModule:
    tree = ast.parse(code)
    analyzer = _Analyzer(code)
    analyzer.visit(tree)
    return ParsedModule(path=path, code=code, tree=tree, functions=analyzer.functions, lines=code.splitlines())
