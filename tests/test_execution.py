# Copyright (c) 2026 Google LLC
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

"""Unit tests for the execution module."""

import gc
import sys
import threading
import time
import unittest
from unittest import mock

# Mock IDA modules before importing the module under test
MOCKED_MODULES = [
    "ida_auto",
    "ida_bytes",
    "ida_dbg",
    "ida_idp",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_hexrays",
    "ida_ida",
    "ida_kernwin",
    "ida_lines",
    "ida_nalt",
    "ida_name",
    "ida_segment",
    "ida_typeinf",
    "ida_xref",
    "idaapi",
    "idautils",
    "idc",
]

module_mocks = {}
for module in MOCKED_MODULES:
  if module in sys.modules:
    module_mocks[module] = sys.modules[module]
  else:
    module_mocks[module] = mock.MagicMock()
sys.modules.update(module_mocks)

# Import the module under test
# Note: This import must happen AFTER the mocking above
# pylint: disable=g-import-not-at-top
from ida_mcp.core import ida_thread
from ida_mcp.core import synchronization
from ida_mcp.tools import execution
from ida_mcp.tools.execution import idapython_eval as _idapython_eval

# pylint: enable=g-import-not-at-top

idapython_eval = getattr(_idapython_eval, "sync_call", _idapython_eval)


class TestPyEval(unittest.TestCase):
  """Tests for the idapython_eval function."""

  def setUp(self):
    super().setUp()
    execution.clear_persistent_globals()
    self.addCleanup(execution.clear_persistent_globals)

  def test_simple_expression(self):
    """Test evaluating a simple mathematical expression."""
    result = idapython_eval("1 + 1")
    self.assertEqual(result["result"], "2")
    self.assertEqual(result["stderr"], "")

  def test_variable_assignment_and_persistence(self):
    """Test that variables defined in one call are available in the next."""
    idapython_eval("x_var = 42", persist_globals=True)
    result = idapython_eval("x_var", persist_globals=True)
    self.assertEqual(result["result"], "42")

  def test_stdout_capture(self):
    """Test capturing standard output."""
    result = idapython_eval("print('Hello, World!')")
    self.assertEqual(result["stdout"].strip(), "Hello, World!")

  def test_syntax_error(self):
    """Test handling of syntax errors."""
    result = idapython_eval("if True")  # Missing colon
    # The exact error message depends on python version, but it should be in
    # stderr
    self.assertIn("SyntaxError", result["stderr"])
    self.assertEqual(result["result"], "")

  def test_runtime_error(self):
    """Test handling of runtime errors."""
    result = idapython_eval("1 / 0")
    self.assertIn("ZeroDivisionError", result["stderr"])

  def test_function_definition(self):
    """Test defining and calling a function."""
    code = """
def add_func(a, b):
    return a + b
"""
    idapython_eval(code, persist_globals=True)
    result = idapython_eval("add_func(10, 20)", persist_globals=True)
    self.assertEqual(result["result"], "30")

  def test_ida_api_call(self):
    """Test interacting with mocked IDA API."""
    # Configure the mock return value
    sys.modules["idc"].get_screen_ea.return_value = 0x1234

    result = idapython_eval("idc.get_screen_ea()")
    self.assertEqual(result["result"], str(0x1234))

  def test_multi_statement_with_expression(self):
    """Test a block with statements ending in an expression."""
    code = """
a = 5
b = 6
a * b
"""
    result = idapython_eval(code)
    self.assertEqual(result["result"], "30")

  def test_complex_logic_persistence(self):
    """Test complex logic spanning multiple calls."""
    idapython_eval("my_list = []", persist_globals=True)
    idapython_eval(
        "for i in range(3): my_list.append(i)", persist_globals=True
    )
    result = idapython_eval("my_list", persist_globals=True)
    self.assertEqual(result["result"], "[0, 1, 2]")

  def test_ast_cancellation_guard_prevents_swallowing_cancelled_error(self):
    """Test that bare except and except BaseException in user code do not swallow _OperationInterrupt."""
    import asyncio  # pylint: disable=g-import-not-at-top

    for handler_clause in ("except:", "except BaseException:", "except* BaseException:"):
      code = f"""
try:
    raise __idamcp_cancelled_error__("cancelled")
{handler_clause}
    swallowed = True
"""
      with self.assertRaises(asyncio.CancelledError):
        idapython_eval(code)

  def test_user_cancelled_error_not_intercepted_by_guard(self):
    """Test that user code can raise and catch its own asyncio.CancelledError normally."""
    code = """
import asyncio
caught_own = False
try:
    raise asyncio.CancelledError("internal task cancel")
except asyncio.CancelledError:
    caught_own = True
caught_own
"""
    result = idapython_eval(code)
    self.assertEqual(result["result"], "True")
    self.assertEqual(result["stderr"], "")

  def test_result_variable_convention_and_no_leak(self):
    """Test setting `result = ...` returns its value and does not leak to the next call."""
    res1 = idapython_eval("result = 123\nx = 1", persist_globals=True)
    self.assertEqual(res1["result"], "123")
    res2 = idapython_eval("x = 2", persist_globals=True)
    self.assertEqual(res2["result"], "")

  def test_entrypoint_functions_run_execute_main(self):
    """Test newly defined `main`, `run`, and `execute` functions are invoked with runtime globals."""
    res_main = idapython_eval("""
def main():
    return "from_main"
""")
    self.assertEqual(res_main["result"], "from_main")

    sys.modules["idc"].get_screen_ea.return_value = 0x401000
    res_run = idapython_eval("""
def run(idc):
    return hex(idc.get_screen_ea())
""")
    self.assertEqual(res_run["result"], "0x401000")

  def test_awaitable_result_evaluated(self):
    """Test that an awaitable coroutine return value is awaited automatically."""
    res = idapython_eval("""
async def main():
    return 99
""")
    self.assertEqual(res["result"], "99")

  def test_awaitable_object_result_evaluated(self):
    """Test that an awaitable that isn't a coroutine is awaited too."""
    res = idapython_eval("""
class Later:
    def __await__(self):
        yield
        return 7
Later()
""")
    self.assertEqual(res["stderr"], "")
    self.assertEqual(res["result"], "7")

  def test_system_exit_caught_cleanly(self):
    """Test that sys.exit() is caught and reported in stderr instead of killing the process."""
    res = idapython_eval("import sys\nprint('before exit')\nsys.exit(7)")
    self.assertEqual(res["stdout"].strip(), "before exit")
    self.assertIn("SystemExit: 7", res["stderr"])
    self.assertEqual(res["result"], "")

  def test_clean_user_traceback_excludes_internal_frames(self):
    """Test that runtime error tracebacks start at <idapython_eval> without internal frames."""
    res = idapython_eval("def boom():\n    return 1 / 0\nboom()")
    self.assertIn('File "<idapython_eval>"', res["stderr"])
    self.assertNotIn("_execute_user_code", res["stderr"])
    self.assertIn("ZeroDivisionError", res["stderr"])


class TestNamespaces(unittest.TestCase):
  """Tests for ephemeral calls and the shared persistent namespace."""

  def setUp(self):
    super().setUp()
    execution.clear_persistent_globals()
    self.addCleanup(execution.clear_persistent_globals)

  def test_default_calls_are_isolated(self):
    """Test that names defined by a default call are gone in the next call."""
    idapython_eval("iso_var = 1\ndef iso_func():\n    return 2")
    result = idapython_eval("('iso_var' in globals(), 'iso_func' in globals())")
    self.assertEqual(result["result"], "(False, False)")

  def test_default_namespace_has_ida_modules_and_helpers(self):
    """Test that a fresh namespace is seeded with IDA modules and helpers."""
    result = idapython_eval(
        "all(name in globals() for name in ('idaapi', 'idc', 'idautils',"
        " 'ida_funcs', 'parse_and_check_ea', 'get_function'))"
    )
    self.assertEqual(result["result"], "True")

  def test_default_call_leaves_persistent_namespace_untouched(self):
    """Test that a default call neither sees nor replaces persistent state."""
    idapython_eval("shared_var = 'kept'", persist_globals=True)
    isolated = idapython_eval("'shared_var' in globals()")
    idapython_eval("shared_var = 'overwritten'")
    persistent = idapython_eval("shared_var", persist_globals=True)
    self.assertEqual(isolated["result"], "False")
    self.assertEqual(persistent["result"], "kept")

  def test_persistent_namespace_self_heals_base_globals(self):
    """Test that rebound or deleted IDA modules and helpers are restored."""
    idapython_eval(
        "idc = None\ndel idaapi\ndel parse_and_check_ea\nuser_var = 5",
        persist_globals=True,
    )
    result = idapython_eval(
        "(idc is not None, 'idaapi' in globals(),"
        " 'parse_and_check_ea' in globals(), user_var)",
        persist_globals=True,
    )
    self.assertEqual(result["result"], "(True, True, True, 5)")

  def test_persistent_entrypoint_not_rerun(self):
    """Test that an entrypoint kept from a previous call is not invoked again."""
    first = idapython_eval("def main():\n    return 'ran'", persist_globals=True)
    second = idapython_eval("unrelated = 1", persist_globals=True)
    self.assertEqual(first["result"], "ran")
    self.assertEqual(second["result"], "")

  def test_persistent_namespace_is_shared_by_all_callers(self):
    """Test that persistent state is one namespace, not keyed by caller."""
    # A worker thread stands in for a call from another agent.
    worker = threading.Thread(
        target=idapython_eval,
        args=("owner = 'agent-1'",),
        kwargs={"persist_globals": True},
    )
    worker.start()
    worker.join(5)
    result = idapython_eval("owner", persist_globals=True)
    self.assertEqual(result["result"], "agent-1")
    self.assertEqual(execution._persistent_globals["owner"], "agent-1")

  def test_clear_persistent_globals_frees_objects_and_reseeds(self):
    """Test that the shutdown clear frees objects and the next call reseeds."""
    code = (
        "import sys, weakref\n"
        "class Probe:\n"
        "    pass\n"
        "probe = Probe()\n"
        "def keep_cycle():\n"
        "    return probe\n"
        "sys._idamcp_probe_ref = weakref.ref(probe)\n"
    )
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
      idapython_eval(code, persist_globals=True)
      self.assertIsNotNone(sys._idamcp_probe_ref())
      execution.clear_persistent_globals()
      self.assertIsNone(sys._idamcp_probe_ref())
    finally:
      if gc_was_enabled:
        gc.enable()
      del sys._idamcp_probe_ref
    result = idapython_eval(
        "('probe' in globals(), 'idc' in globals())", persist_globals=True
    )
    self.assertEqual(result["result"], "(False, True)")

  def test_default_namespace_is_cleared_after_call(self):
    """Test that a default call frees its objects without waiting for the GC."""
    # keep_cycle creates a function -> __globals__ -> namespace cycle that only
    # the GC could break if the namespace were not cleared.
    code = (
        "import sys, weakref\n"
        "class Probe:\n"
        "    pass\n"
        "probe = Probe()\n"
        "def keep_cycle():\n"
        "    return probe\n"
        "sys._idamcp_probe_ref = weakref.ref(probe)\n"
    )
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
      idapython_eval(code)
      self.assertIsNone(sys._idamcp_probe_ref())
      idapython_eval(code, persist_globals=True)
      self.assertIsNotNone(sys._idamcp_probe_ref())
    finally:
      if gc_was_enabled:
        gc.enable()
      del sys._idamcp_probe_ref

  def test_result_str_may_use_snippet_globals(self):
    """Test that the result is stringified before the namespace is cleared."""
    code = (
        "FMT = 'value=%d'\n"
        "class Shown:\n"
        "    def __str__(self):\n"
        "        return FMT % 7\n"
        "Shown()"
    )
    result = idapython_eval(code)
    self.assertEqual(result["stderr"], "")
    self.assertEqual(result["result"], "value=7")

  def test_result_str_error_reported_in_stderr(self):
    """Test that a failing __str__ on the result is reported like user errors."""
    code = (
        "class Broken:\n"
        "    def __str__(self):\n"
        "        raise ValueError('cannot render')\n"
        "Broken()"
    )
    result = idapython_eval(code)
    self.assertEqual(result["result"], "")
    self.assertIn("ValueError: cannot render", result["stderr"])

  def test_dataclass_with_postponed_annotations(self):
    """Test @dataclass under `from __future__ import annotations` (no __name__)."""
    code = (
        "from __future__ import annotations\n"
        "import dataclasses\n"
        "@dataclasses.dataclass\n"
        "class Point:\n"
        "    x: int\n"
        "    y: int = 0\n"
        "Point(1)"
    )
    result = idapython_eval(code)
    self.assertEqual(result["stderr"], "")
    self.assertEqual(result["result"], "Point(x=1, y=0)")


class TestTimeout(unittest.TestCase):
  """Tests for the timeout parameter, enforced by @idawrite."""

  def setUp(self):
    super().setUp()
    # Dispatch calls as in headless mode, but run them on this thread instead of
    # IDA's main thread, so that @idawrite arms the timeout.
    for patcher in (
        mock.patch.object(sys.modules["idaapi"], "is_headless", True),
        mock.patch("idaapi.is_main_thread", return_value=False),
        mock.patch.object(
            ida_thread, "execute_sync", lambda func, unused_mode=0: func()
        ),
        mock.patch.object(synchronization, "_flush_after_write"),
    ):
      patcher.start()
      self.addCleanup(patcher.stop)

  def test_default_timeout_is_360_seconds(self):
    """Test that a call without a timeout is limited to 360 seconds."""
    timeouts = []

    def recording_sync_wrapper(ff, unused_mode, timeout=None):
      timeouts.append(timeout)
      return ff()

    with mock.patch.object(
        synchronization, "sync_wrapper", recording_sync_wrapper
    ):
      idapython_eval("1")
    self.assertEqual(timeouts, [360.0])

  def test_runaway_code_times_out(self):
    """Test that code still running after the timeout is interrupted."""
    code = "import time\nwhile True:\n    time.sleep(0.001)"
    started_at = time.monotonic()
    with self.assertRaises(TimeoutError) as ctx:
      idapython_eval(code, timeout=0.2)
    self.assertLess(time.monotonic() - started_at, 2.0)
    # Nothing was printed, so there is nothing to add to the message.
    self.assertEqual(str(ctx.exception), "Operation timed out after 0.20s")

  def test_timeout_error_includes_output_printed_so_far(self):
    """Test that the timeout error ends with the stdout and stderr so far."""
    spin = "def spin():\n    while True:\n        pass\n"
    for prints, expected_output in (
        ("print('started')\n", "stdout:\nstarted"),
        ("print('slow', file=sys.stderr)\n", "stderr:\nslow"),
        (
            # Also output printed while the interrupt unwinds the code.
            "print('started')\n"
            "print('slow', file=sys.stderr)\n"
            "try:\n"
            "    spin()\n"
            "finally:\n"
            "    print('cleaned up')\n",
            "stdout:\nstarted\ncleaned up\n\nstderr:\nslow",
        ),
    ):
      code = f"import sys\n{spin}{prints}spin()\n"
      with self.subTest(expected_output=expected_output):
        with self.assertRaises(TimeoutError) as ctx:
          idapython_eval(code, timeout=0.2)
        self.assertEqual(
            str(ctx.exception),
            f"Operation timed out after 0.20s\n\n{expected_output}",
        )

  def _clear_namespaces_slowly(self, seconds: float) -> None:
    """Makes clearing a namespace take `seconds`, like slow destructors."""
    prepare_namespace = execution._prepare_namespace

    class SlowClearNamespace(dict):

      def clear(self):
        time.sleep(seconds)
        super().clear()

    patcher = mock.patch.object(
        execution,
        "_prepare_namespace",
        lambda persist: SlowClearNamespace(prepare_namespace(persist)),
    )
    patcher.start()
    self.addCleanup(patcher.stop)

  def test_timeout_during_namespace_clear_keeps_output(self):
    """Test a timeout that lands in the clear after the code finished."""
    # The code finishes at once. The timeout comes 0.2s into the 0.3s clear,
    # and its re-interrupt (0.45s) after the call has failed.
    self._clear_namespaces_slowly(0.3)
    with self.assertRaises(TimeoutError) as ctx:
      idapython_eval("print('started')", timeout=0.2)
    self.assertEqual(
        str(ctx.exception),
        "Operation timed out after 0.20s\n\nstdout:\nstarted",
    )

  def test_reinterrupt_during_namespace_clear_keeps_output(self):
    """Test a re-interrupt that lands in the clear after a timeout."""
    # The timeout ends the loop at 0.2s. Its re-interrupt comes 0.25s into the
    # 0.5s clear, and the next one (0.95s) after the call has failed.
    self._clear_namespaces_slowly(0.5)
    with self.assertRaises(TimeoutError) as ctx:
      idapython_eval("print('started')\nwhile True:\n    pass", timeout=0.2)
    self.assertEqual(
        str(ctx.exception),
        "Operation timed out after 0.20s\n\nstdout:\nstarted",
    )

  def test_user_handlers_cannot_swallow_the_timeout(self):
    """Test that bare except and except BaseException cannot catch it."""
    for handler_clause in ("except:", "except BaseException:"):
      code = (
          "import time\n"
          "try:\n"
          "    while True:\n"
          "        time.sleep(0.001)\n"
          f"{handler_clause}\n"
          "    pass\n"
          "while True:\n"
          "    time.sleep(0.001)\n"
      )
      with self.subTest(handler_clause=handler_clause):
        started_at = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, "timed out"):
          idapython_eval(code, timeout=0.2)
        # Not interrupted only by the retry, which would come 250ms later.
        self.assertLess(time.monotonic() - started_at, 0.4)

  def test_async_code_times_out(self):
    """Test the timeout of a coroutine, which asyncio.run() runs as a task."""
    code = (
        "import time\n"
        "async def main():\n"
        "    while True:\n"
        "        time.sleep(0.001)\n"
    )
    with self.assertRaisesRegex(TimeoutError, "timed out after 0.20s"):
      idapython_eval(code, timeout=0.2)

  def test_timeout_is_reported_when_asyncio_replaces_the_interrupt(self):
    """Test a timeout that asyncio turns into a plain CancelledError."""
    # The interrupt lands in spin(); asyncio.shield() then raises a new
    # CancelledError in main(), which is all that reaches @idawrite.
    code = (
        "import asyncio\n"
        "async def spin():\n"
        "    while True:\n"
        "        pass\n"
        "async def main():\n"
        "    await asyncio.shield(asyncio.ensure_future(spin()))\n"
    )
    with self.assertRaisesRegex(TimeoutError, "timed out after 0.20s"):
      idapython_eval(code, timeout=0.2)

  def test_code_that_finishes_in_time_returns_its_output(self):
    """Test that a timeout does not affect code that finishes in time."""
    result = idapython_eval("print('hi')\n6 * 7", timeout=1)
    self.assertEqual(result["stdout"], "hi\n")
    self.assertEqual(result["result"], "42")
    self.assertEqual(result["stderr"], "")

  def test_invalid_timeout_is_rejected_before_the_code_runs(self):
    """Test that a timeout must be a positive number of seconds."""
    for value in (0, -5):
      with self.subTest(value=value):
        with self.assertRaisesRegex(ValueError, "timeout must be"):
          idapython_eval("x_ran = True", persist_globals=True, timeout=value)
    self.assertNotIn("x_ran", execution._persistent_globals)


if __name__ == "__main__":
  unittest.main()
