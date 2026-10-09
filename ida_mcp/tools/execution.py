# Copyright (c) 2026 Google LLC
# Copyright (c) 2025 Duncan Ogilvie
# Copyright (c) 2026 Hex-Rays SA
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Module for executing Python code in the IDA Pro environment."""

import ast
import asyncio
from collections.abc import Awaitable, Callable
import contextlib
import inspect
import io
import sys
import traceback
from typing import Annotated, Any, Dict

from ida_mcp.core.decorators import _OperationInterrupt
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.decorators import unsafe
from ida_mcp.core.synchronization import idawrite
from ida_mcp.utils import helper

# IDA modules and runtime helpers that seed every execution namespace.
_base_globals: Dict[str, Any] = {}
# The namespace of `persist_globals=True` calls, shared by all callers. Only
# accessed on IDA's main thread.
_persistent_globals: Dict[str, Any] = {}
_CANCEL_EXC_NAME = "__idamcp_cancelled_error__"
_USER_CODE_FILENAME = "<idapython_eval>"


# Adapted from ida-nexus: _protect_operation_interrupt in ida_nexus/_runtime.py.
def _protect_cancellation(module: ast.Module) -> None:
  """Prepend an `except _OperationInterrupt: raise` handler to every user try block."""
  for node in ast.walk(module):
    if not isinstance(node, (ast.Try, ast.TryStar)) or not node.handlers:
      continue
    anchor = node.handlers[0]
    exc_type = ast.copy_location(
        ast.Name(id=_CANCEL_EXC_NAME, ctx=ast.Load()), anchor.type or anchor
    )
    if isinstance(node, ast.TryStar):
      # A bare raise inside `except*` re-raises a synthetic BaseExceptionGroup.
      # Raise a fresh sentinel instance for the outer cancellation handler.
      reraised_interrupt = ast.copy_location(
          ast.Name(id=_CANCEL_EXC_NAME, ctx=ast.Load()),
          anchor.type or anchor,
      )
      reraiser = ast.copy_location(ast.Raise(exc=reraised_interrupt), anchor)
    else:
      reraiser = ast.copy_location(ast.Raise(), anchor)
    handler = ast.copy_location(
        ast.ExceptHandler(type=exc_type, name=None, body=[reraiser]), anchor
    )
    node.handlers.insert(0, handler)


# Adapted from ida-nexus: _format_user_traceback in ida_nexus/_runtime.py.
def _format_user_traceback(
    error: BaseException, trace_filename: str = _USER_CODE_FILENAME
) -> str:
  """Format only the user-supplied code portion of an execution failure."""
  if isinstance(error, SyntaxError):
    return "".join(traceback.format_exception_only(error))
  frames = traceback.extract_tb(error.__traceback__)
  first_user_frame = next(
      (
          index
          for index, frame in enumerate(frames)
          if frame.filename == trace_filename
      ),
      None,
  )
  if first_user_frame is None:
    return "".join(traceback.format_exception(error))
  return (
      "Traceback (most recent call last):\n"
      + "".join(traceback.format_list(frames[first_user_frame:]))
      + "".join(traceback.format_exception_only(error))
  )


def _add_output_notes(error: BaseException, stdout: str, stderr: str) -> None:
  """Adds the output printed so far, one note per non-empty stream, to `error`.

  Args:
    error: The exception that interrupted the code.
    stdout: The standard output captured so far.
    stderr: The standard error captured so far.
  """
  for name, text in (("stdout", stdout), ("stderr", stderr)):
    if text.strip():
      error.add_note(f"{name}:\n{text.rstrip()}")


async def _await(value: Awaitable[Any]) -> Any:
  """Awaits `value`, so that asyncio.run can run awaitables of any kind.

  asyncio.run itself accepts only coroutines, but a snippet may evaluate to a
  Future or to an object with __await__.
  """
  return await value


def _type_name(value: Any) -> str:
  """Returns the type name of `value`, e.g. "int" or "ida_funcs.func_t"."""
  value_type = type(value)
  # A class that a snippet creates with type() has no __module__, because the
  # namespace has no __name__ (see _get_base_globals).
  module = getattr(value_type, "__module__", None)
  if module in (None, "builtins"):
    return value_type.__qualname__
  return f"{module}.{value_type.__qualname__}"


# Adapted from ida-nexus: _invoke_callable in ida_nexus/_runtime.py.
def _invoke_callable(
    function: Callable[..., Any],
    runtime: Dict[str, Any],
) -> Any:
  """Invoke a newly defined `run`/`execute`/`main` entrypoint with runtime args."""
  signature = inspect.signature(function)
  args: list[Any] = []
  kwargs: dict[str, Any] = {}
  for parameter in signature.parameters.values():
    if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
      continue
    if parameter.kind is inspect.Parameter.VAR_KEYWORD:
      for name, value in runtime.items():
        kwargs.setdefault(name, value)
      continue
    if parameter.name not in runtime:
      if parameter.default is inspect.Parameter.empty:
        raise TypeError(
            f"missing runtime value for parameter '{parameter.name}'"
        )
      continue
    value = runtime[parameter.name]
    if parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
      args.append(value)
    else:
      kwargs[parameter.name] = value
  return function(*args, **kwargs)


# Adapted from ida-nexus: _execute_user_code in ida_nexus/_runtime.py.
def _execute_user_code(
    code: str,
    namespace: Dict[str, Any],
    runtime: Dict[str, Any],
    filename: str = _USER_CODE_FILENAME,
) -> Any:
  """Compile and execute user Python code with expression/entrypoint/result conventions."""
  stripped = code.strip()
  if not stripped:
    return None

  module = ast.parse(stripped, filename=filename, mode="exec")
  _protect_cancellation(module)
  namespace[_CANCEL_EXC_NAME] = _OperationInterrupt
  previous_entrypoints = {
      name: namespace.get(name) for name in ("run", "execute", "main")
  }
  # `result` is a per-call output slot, not persistent REPL state.
  namespace.pop("result", None)
  try:
    if len(module.body) == 1 and isinstance(module.body[0], ast.Expr):
      expression = ast.Expression(module.body[0].value)
      # pylint: disable=eval-used
      return eval(
          compile(expression, filename, "eval"),
          namespace,
          namespace,
      )

    if module.body and isinstance(module.body[-1], ast.Expr):
      prefix = ast.Module(
          body=module.body[:-1], type_ignores=module.type_ignores
      )
      if prefix.body:
        # pylint: disable=exec-used
        exec(
            compile(prefix, filename, "exec"),
            namespace,
            namespace,
        )
      expression = ast.Expression(module.body[-1].value)
      # pylint: disable=eval-used
      return eval(
          compile(expression, filename, "eval"),
          namespace,
          namespace,
      )

    # pylint: disable=exec-used
    exec(
        compile(module, filename, "exec"),
        namespace,
        namespace,
    )
    for name in ("run", "execute", "main"):
      candidate = namespace.get(name)
      if callable(candidate) and candidate is not previous_entrypoints[name]:
        return _invoke_callable(candidate, runtime)
    return namespace.get("result")
  finally:
    namespace.pop("result", None)


def _lazy_import(module_name):
  try:
    return __import__(module_name)
  except ImportError:
    return None


def _get_base_globals() -> Dict[str, Any]:
  """Returns the IDA modules and helpers that seed every namespace.

  `__name__` is deliberately absent: it then resolves to builtins.__name__, a
  real module, which e.g. `@dataclass` with `from __future__ import
  annotations` relies on. "__main__" would also re-run `main()` guarded by
  `if __name__ == "__main__"` on top of the entrypoint convention.
  """
  if not _base_globals:
    # Standard IDA modules
    modules = [
        "ida_allins",
        "ida_auto",
        "ida_bitrange",
        "ida_bytes",
        "ida_dbg",
        "ida_dirtree",
        "ida_diskio",
        "ida_domain",
        "ida_entry",
        "ida_expr",
        "ida_fixup",
        "ida_fpro",
        "ida_frame",
        "ida_funcs",
        "ida_gdl",
        "ida_graph",
        "ida_hexrays",
        "ida_ida",
        "ida_idd",
        "ida_idp",
        "ida_ieee",
        "ida_kernwin",
        "ida_libfuncs",
        "ida_lines",
        "ida_loader",
        "ida_merge",
        "ida_mergemod",
        "ida_moves",
        "ida_nalt",
        "ida_name",
        "ida_netnode",
        "ida_offset",
        "ida_pro",
        "ida_problems",
        "ida_range",
        "ida_regfinder",
        "ida_registry",
        "ida_idaapi",
        "ida_search",
        "ida_segment",
        "ida_segregs",
        "ida_srclang",
        "ida_strlist",
        "ida_struct",
        "ida_tryblks",
        "ida_typeinf",
        "ida_ua",
        "ida_undo",
        "ida_xref",
        "ida_enum",
        "idaapi",
        "idc",
        "idautils",
    ]

    for name in modules:
      if name in sys.modules:
        _base_globals[name] = sys.modules[name]
      else:
        _base_globals[name] = _lazy_import(name)

  _base_globals["__builtins__"] = __builtins__
  _base_globals["parse_and_check_ea"] = helper.parse_and_check_ea
  _base_globals["get_function"] = helper.get_function
  _base_globals[_CANCEL_EXC_NAME] = _OperationInterrupt
  return _base_globals


def _prepare_namespace(persist_globals: bool) -> Dict[str, Any]:
  """Returns the namespace for a call. Must run on IDA's main thread.

  Args:
    persist_globals: Whether to return the shared persistent namespace instead
      of a fresh one, which the caller must clear after the call.
  """
  if not persist_globals:
    return dict(_get_base_globals())
  # Runtime-owned modules and helpers remain valid even if a prior snippet
  # rebound or deleted them.
  # Adapted from ida-nexus: IDARuntime.execute_python in ida_nexus/_runtime.py.
  _persistent_globals.update(_get_base_globals())
  return _persistent_globals


def clear_persistent_globals() -> None:
  """Clears the shared persistent namespace. Must run on IDA's main thread.

  The namespace may hold SWIG-wrapped IDA objects whose destructors call into
  IDA, so shutdown clears it while the database is still open.
  """
  _persistent_globals.clear()


@jsonrpc
@unsafe
@idawrite
def idapython_eval(
    code: Annotated[str, "Python code to execute"],
    persist_globals: Annotated[
        bool,
        "If true, the code runs in one namespace shared by all callers, so"
        " variables, functions, and imports persist across calls and are"
        " visible to every agent. If false, the code runs in a fresh namespace"
        " that is discarded after the call.",
    ] = False,
    timeout: Annotated[
        float,
        "Maximum time in seconds the code may run. Code that runs longer is"
        " interrupted, and the call fails with a timeout error that includes"
        " the output printed so far. Time spent waiting for other tool calls to"
        " finish does not count.",
    ] = 360.0,
) -> Dict[str, Any]:
  """Execute Python code in IDA context.

  Returns dict with result/result_type/stdout/stderr: result is str() of the
  value, and result_type its type, e.g. "int" or "ida_funcs.func_t" (both are
  empty if the code raises). Has access to all IDA API modules.
  Supports Jupyter-style evaluation (returns the value of the last expression).
  Each call runs in a fresh namespace unless persist_globals is set; objects
  that must outlive the call (hooks, timers, callbacks) need persist_globals.
  """
  del timeout  # Enforced by @idawrite.
  namespace = _prepare_namespace(persist_globals)

  stdout_capture = io.StringIO()
  stderr_capture = io.StringIO()
  result_text = ""
  result_type = ""

  try:
    try:
      with (
          contextlib.redirect_stdout(stdout_capture),
          contextlib.redirect_stderr(stderr_capture),
      ):
        result_value = _execute_user_code(
            code,
            namespace,
            namespace,
            filename=_USER_CODE_FILENAME,
        )
        if inspect.isawaitable(result_value):
          result_value = asyncio.run(_await(result_value))
        # Stringify before the namespace is cleared, since __str__ may use
        # globals defined by the snippet.
        result_text = str(result_value)
        result_type = _type_name(result_value)
    except (Exception, SystemExit) as exc:  # pylint: disable=broad-exception-caught
      # Catch both Exception and SystemExit so `sys.exit()` in user scripts is
      # reported cleanly in stderr instead of terminating the worker/GUI thread.
      print(
          _format_user_traceback(exc, _USER_CODE_FILENAME),
          end="",
          file=stderr_capture,
      )
    finally:
      if not persist_globals:
        # Break function -> __globals__ -> namespace cycles now, so objects the
        # snippet created (including SWIG-wrapped IDA objects) are freed here on
        # IDA's main thread instead of by a later GC pass on another thread.
        namespace.clear()
  except BaseException as exc:
    # The interrupt for a cancel or timeout, which @idawrite turns into
    # CancelledError or ToolTimeoutError. A timeout error includes these notes,
    # so the client still gets the output printed before the timeout. Handled
    # out here so that it also covers an interrupt raised while the namespace
    # is cleared, which replaces the interrupt that was unwinding.
    _add_output_notes(exc, stdout_capture.getvalue(), stderr_capture.getvalue())
    raise

  return {
      "result": result_text,
      "result_type": result_type,
      "stdout": stdout_capture.getvalue(),
      "stderr": stderr_capture.getvalue(),
  }
