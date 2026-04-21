from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from app.parsers.python_ast_parser import ParsedModule, FunctionInfo


USER_INPUT_CALLS = {"input"}
SQL_SINKS = {"execute", "cursor.execute", "cur.execute"}
HTTP_SINKS = {"requests.get", "requests.post", "requests.request", "get", "post"}
COMMAND_SINKS = {"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"}


@dataclass
class TraceEvidence:
    source_file: str
    source_line: int
    sink_file: str
    sink_line: int
    source_code: str
    sink_code: str
    source_function: Optional[str]
    sink_function: Optional[str]
    trace_steps: List[str]
    variable_names: List[str]
    sink_call: str
    sink_args: List[str]
    assignment_expr: Optional[str] = None


class SourceSinkAnalyzer:
    def __init__(self, modules: Dict[str, ParsedModule]):
        self.modules = modules

    def build_evidence(self, source_line: int, sink_line: int) -> TraceEvidence:
        source_module, source_fn = self._find_line(source_line)
        sink_module, sink_fn = self._find_line(sink_line)
        if not source_module or not sink_module:
            raise ValueError("Could not map source/sink lines to modules")

        source_code = source_module.get_line(source_line)
        sink_code = sink_module.get_line(sink_line)
        sink_call_name, sink_args = self._find_sink_call(sink_module, sink_fn, sink_line)
        variable_names = self._infer_user_variables(source_module, source_fn, source_line)
        call_path = self._infer_interprocedural_steps(source_module, source_fn, sink_module, sink_fn, variable_names)
        assignment_expr = self._related_assignment_expr(sink_module, sink_fn, sink_args)

        steps = [f"source at {source_module.path}:{source_line} -> {source_code.strip()}"]
        steps.extend(call_path)
        if assignment_expr:
            steps.append(f"assignment related to sink argument: {assignment_expr}")
        steps.append(f"sink at {sink_module.path}:{sink_line} -> {sink_code.strip()}")

        return TraceEvidence(
            source_file=source_module.path,
            source_line=source_line,
            sink_file=sink_module.path,
            sink_line=sink_line,
            source_code=source_code,
            sink_code=sink_code,
            source_function=source_fn.name if source_fn else None,
            sink_function=sink_fn.name if sink_fn else None,
            trace_steps=steps,
            variable_names=variable_names,
            sink_call=sink_call_name,
            sink_args=sink_args,
            assignment_expr=assignment_expr,
        )

    def _find_line(self, line: int):
        for module in self.modules.values():
            if 1 <= line <= len(module.lines):
                fn = module.find_function_by_line(line)
                return module, fn
        return None, None

    def _find_sink_call(self, module: ParsedModule, fn: Optional[FunctionInfo], sink_line: int):
        if fn:
            for call in fn.calls:
                if call.line == sink_line:
                    return call.name, call.args_repr
        return "unknown", []

    def _infer_user_variables(self, module: ParsedModule, fn: Optional[FunctionInfo], source_line: int) -> List[str]:
        if not fn:
            return []
        variables: List[str] = []
        for call in fn.calls:
            if call.line == source_line and call.name in USER_INPUT_CALLS:
                variables.extend(call.assigns_to)
        return variables

    def _infer_interprocedural_steps(
        self,
        source_module: ParsedModule,
        source_fn: Optional[FunctionInfo],
        sink_module: ParsedModule,
        sink_fn: Optional[FunctionInfo],
        variables: List[str],
    ) -> List[str]:
        steps: List[str] = []
        if source_fn:
            for call in source_fn.calls:
                if sink_fn and call.name == sink_fn.name:
                    steps.append(
                        f"call from function {source_fn.name} to {sink_fn.name} with args {', '.join(call.args_repr)}"
                    )
        if sink_fn and variables:
            overlap = [v for v in variables if v in sink_fn.params]
            if overlap:
                steps.append(
                    f"user-controlled variables propagated into function {sink_fn.name} parameters: {', '.join(overlap)}"
                )
        return steps

    def _related_assignment_expr(self, module: ParsedModule, fn: Optional[FunctionInfo], sink_args: List[str]) -> Optional[str]:
        if not fn or not sink_args:
            return None
        first = sink_args[0]
        return fn.assignments.get(first)
