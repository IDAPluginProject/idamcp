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

"""Unit tests for cancellation and interruption mechanisms."""

import asyncio
import contextvars
import pathlib
import sqlite3
import sys
import threading
import time
import typing
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

# Mock IDA modules before importing ida_mcp modules
MOCKED_MODULES = [
    "idaapi",
    "ida_auto",
    "ida_bytes",
    "ida_dbg",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_gdl",
    "ida_hexrays",
    "ida_ida",
    "ida_idaapi",
    "ida_idp",
    "ida_kernwin",
    "ida_lines",
    "ida_nalt",
    "ida_name",
    "ida_segment",
    "ida_typeinf",
    "ida_xref",
    "idautils",
    "idc",
]
for module in MOCKED_MODULES:
  if module not in sys.modules:
    sys.modules[module] = mock.MagicMock()

# pylint: disable=g-import-not-at-top
from ida_mcp.core.decorators import cancellation_profile
from ida_mcp.core.decorators import cancellation_token_var
from ida_mcp.core.decorators import CancellationToken
from ida_mcp.core.decorators import is_ida_mcp_canceller
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.decorators import make_cancellation_profile_func
from ida_mcp.core.decorators import register_cancel_callback
from ida_mcp.core.ida_thread import _safe_set_exception
from ida_mcp.core.ida_thread import _safe_set_result
from ida_mcp.core.ida_thread import IDATask
from ida_mcp.core.synchronization import async_wrapper
from ida_mcp.core.synchronization import idaread
from ida_mcp.core.synchronization import idawrite
from ida_mcp.core.synchronization import IDASafety
from ida_mcp.core.synchronization import IDASyncError
from ida_mcp.core.synchronization import sync_wrapper
from ida_mcp.tools.query import interruptible_sqlite

# pylint: enable=g-import-not-at-top


class TestCancellationToken(unittest.TestCase):
  """Tests for CancellationToken and callback handling."""

  def test_token_lifecycle(self):
    """Tests cancellation token state changes and callback triggering."""
    token = CancellationToken()
    self.assertFalse(token.is_cancelled)
    self.assertFalse(token.is_set())

    called = []
    token.register_callback(lambda: called.append(1))

    token.cancel()
    self.assertTrue(token.is_cancelled)
    self.assertTrue(token.is_set())
    self.assertEqual(called, [1])

    # Subsequent cancels do nothing
    token.cancel()
    self.assertEqual(called, [1])

    # Callbacks registered after cancel are executed immediately
    late_called = []
    token.register_callback(lambda: late_called.append(2))
    self.assertEqual(late_called, [2])

  def test_unregister_callback(self):
    """Tests unregistering a callback before cancellation."""
    token = CancellationToken()
    called = []
    unregister = token.register_callback(lambda: called.append(1))
    unregister()
    token.cancel()
    self.assertEqual(called, [])

  def test_callback_exception_handling(self):
    """Tests that exceptions in callbacks do not abort subsequent callbacks."""
    token = CancellationToken()
    called = []

    def failing_cb():
      raise ValueError("Boom")

    token.register_callback(failing_cb)
    token.register_callback(lambda: called.append(1))

    # Should not raise despite failing_cb
    token.cancel()
    self.assertEqual(called, [1])

  def test_register_cancel_callback_context_manager(self):
    """Tests register_cancel_callback context manager scope."""
    token = CancellationToken()
    var_token = cancellation_token_var.set(token)
    called = []
    try:
      with register_cancel_callback(lambda: called.append(1)):
        self.assertEqual(called, [])
      # Out of context -> unregistered
      token.cancel()
      self.assertEqual(called, [])
    finally:
      cancellation_token_var.reset(var_token)


class TestSQLiteInterruption(unittest.TestCase):
  """Tests for SQLite query interruption via conn.interrupt()."""

  def test_sqlite_query_interruption(self):
    """Tests that conn.interrupt terminates heavy in-progress SQLite queries."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    token = CancellationToken()
    var_token = cancellation_token_var.set(token)

    query_error = []

    def run_heavy_query():
      try:
        with interruptible_sqlite(conn):
          # Infinite / very slow recursive query
          conn.execute(
              "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM"
              " cnt) SELECT count(*) FROM cnt CROSS JOIN cnt AS b"
          )
      except Exception as e:  # pylint: disable=broad-exception-caught
        query_error.append(e)
      except asyncio.CancelledError as e:
        query_error.append(e)

    ctx = contextvars.copy_context()
    t = threading.Thread(target=ctx.run, args=(run_heavy_query,))
    t.start()

    # Wait briefly for query to start in C code
    time.sleep(0.05)

    # Cancel token (which invokes conn.interrupt())
    token.cancel()
    t.join(timeout=2.0)
    cancellation_token_var.reset(var_token)

    self.assertFalse(t.is_alive(), "Worker thread did not terminate in time")
    self.assertEqual(len(query_error), 1)
    self.assertIsInstance(query_error[0], asyncio.CancelledError)

    # Verify connection remains valid and operational
    cursor = conn.execute("SELECT 42")
    self.assertEqual(cursor.fetchone()[0], 42)
    conn.close()


class TestSyncWrapperCancellation(unittest.TestCase):
  """Tests for sync_wrapper cancellation checks."""

  def test_sync_wrapper_pre_cancelled(self):
    """Verifies sync_wrapper raises if cancelled before execution."""
    token = CancellationToken()
    token.cancel()
    var_token = cancellation_token_var.set(token)
    try:
      executed = []
      with self.assertRaises(asyncio.CancelledError):
        sync_wrapper(lambda: executed.append(1), IDASafety.SAFE_READ)
      self.assertEqual(executed, [])
    finally:
      cancellation_token_var.reset(var_token)


class TestAsyncWrapperCancellation(unittest.IsolatedAsyncioTestCase):
  """Tests for async_wrapper cancellation checks and alias compatibility."""

  async def test_async_wrapper_pre_cancelled(self):
    """Verifies async_wrapper raises if cancelled before execution."""
    token = CancellationToken()
    token.cancel()
    var_token = cancellation_token_var.set(token)
    try:
      executed = []
      with self.assertRaises(asyncio.CancelledError):
        await async_wrapper(lambda: executed.append(1), IDASafety.SAFE_READ)
      self.assertEqual(executed, [])
    finally:
      cancellation_token_var.reset(var_token)

  async def test_invalid_safety_mode(self):
    """Tests that invalid safety modes raise IDASyncError."""
    invalid_mode = typing.cast(IDASafety, 999)
    with self.assertRaises(IDASyncError):
      sync_wrapper(lambda: None, invalid_mode)
    with self.assertRaises(IDASyncError):
      await async_wrapper(lambda: None, invalid_mode)

  async def test_safe_setters_on_cancelled_future(self):
    """Tests _safe_set_result and _safe_set_exception

    Ensure these functions don't raise InvalidStateError on cancelled future.
    """
    loop = asyncio.get_running_loop()
    fut1 = loop.create_future()
    fut1.cancel()
    # Should not raise InvalidStateError
    _safe_set_result(fut1, "value")

    fut2 = loop.create_future()
    fut2.cancel()
    # Should not raise InvalidStateError
    _safe_set_exception(fut2, RuntimeError("error"))

  async def test_idatask_pre_cancelled(self):
    """Tests that IDATask with pre-cancellation.

    IDATask should not execute func if future is cancelled in queue.
    """
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    fut.cancel()

    executed = []
    task = IDATask(lambda: executed.append(1), loop=loop, future=fut)
    task()
    self.assertEqual(executed, [])

  async def test_idasync_dual_behavior_and_sync_call(self):
    """Tests _idasync behavior.

    The wrapper is expected to return coroutine in active loop and sync_call
    returns directly.
    """
    executed = []

    @idaread
    def my_tool(x: int) -> int:
      executed.append(x)
      return x * 2

    # In active asyncio loop, calling my_tool directly returns an awaitable
    # coroutine
    coro = my_tool(5)
    self.assertTrue(asyncio.iscoroutine(coro))

    # Mocking idaapi.is_main_thread to True so run_in_main executes ff()
    with mock.patch("idaapi.is_main_thread", return_value=True):
      res = await coro
      self.assertEqual(res, 10)

      # Calling .sync_call directly executes synchronously even in active loop
      sync_res = my_tool.sync_call(7)
      self.assertEqual(sync_res, 14)

    self.assertEqual(executed, [5, 7])


class TestJSONRPCDecoratorCancellation(unittest.IsolatedAsyncioTestCase):
  """Tests for @jsonrpc decorator cancellation flow."""

  async def test_sync_tool_cancellation(self):
    """Tests that a synchronous tool wrapped with @jsonrpc cancels cleanly."""
    stop_event = threading.Event()

    @jsonrpc
    def slow_tool(delay: float) -> str:
      with register_cancel_callback(stop_event.set):
        for _ in range(int(delay * 100)):
          if stop_event.is_set():
            break
          time.sleep(0.01)
        return "done"

    task = asyncio.create_task(slow_tool(delay=1.0))
    await asyncio.sleep(0.05)

    task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await task
    self.assertTrue(stop_event.is_set())


class TestCancellationProfileReuse(unittest.TestCase):
  """Tests for profile function tagging, idempotent reuse, and stacking."""

  def tearDown(self):
    super().tearDown()
    sys.setprofile(None)

  def test_make_cancellation_profile_func_tagging(self):
    """Verifies that make_cancellation_profile_func sets metadata and aborts."""
    token = CancellationToken()
    prof = make_cancellation_profile_func(token)

    self.assertTrue(getattr(prof, "is_ida_mcp_canceller", False))
    self.assertIs(getattr(prof, "token", None), token)

    # Should not raise when token is not cancelled
    prof(None, "call", None)

    # Should raise CancelledError when token is cancelled
    token.cancel()
    with self.assertRaises(asyncio.CancelledError):
      prof(None, "call", None)

  def test_is_ida_mcp_canceller_logic(self):
    """Verifies is_ida_mcp_canceller."""
    token1 = CancellationToken()
    token2 = CancellationToken()
    prof1 = make_cancellation_profile_func(token1)

    self.assertTrue(is_ida_mcp_canceller(prof1))
    self.assertTrue(is_ida_mcp_canceller(prof1, token1))
    self.assertFalse(is_ida_mcp_canceller(prof1, token2))

    self.assertFalse(is_ida_mcp_canceller(None))
    self.assertFalse(is_ida_mcp_canceller(lambda f, e, a: None))
    self.assertFalse(is_ida_mcp_canceller("string"))

  def test_cancellation_profile_idempotent_reuse(self):
    """Verifies nested cancellation_profile calls reuse the active hook.

    When invoked with the same cancellation token, the existing profile
    function is preserved rather than re-registered.
    """
    token = CancellationToken()
    self.assertIsNone(sys.getprofile())

    with cancellation_profile(token):
      prof1 = sys.getprofile()
      self.assertTrue(is_ida_mcp_canceller(prof1, token))

      # Nested scope with same token
      with cancellation_profile(token):
        prof2 = sys.getprofile()
        # Must be the exact same function object, not replaced
        self.assertIs(prof1, prof2)

      # After nested scope exit, still prof1
      self.assertIs(sys.getprofile(), prof1)

    # After outer scope exit, profile is cleared
    self.assertIsNone(sys.getprofile())

  def test_cancellation_profile_token_mismatch_stacking(self):
    """Verifies nested calls with different tokens stack and restore.

    When an inner scope has a different cancellation token, a new profile
    hook is pushed and the previous hook is restored upon exit.
    """
    token1 = CancellationToken()
    token2 = CancellationToken()

    with cancellation_profile(token1):
      prof1 = sys.getprofile()
      self.assertIs(getattr(prof1, "token", None), token1)

      with cancellation_profile(token2):
        prof2 = sys.getprofile()
        self.assertIsNot(prof1, prof2)
        self.assertIs(getattr(prof2, "token", None), token2)

      self.assertIs(sys.getprofile(), prof1)

    self.assertIsNone(sys.getprofile())

  def test_nested_idatools_profile_reuse(self):
    """Verifies nested IDA tools retain the outer profile hook.

    An IDA tool called from another IDA tool on the main thread executes
    cleanly under the outer profile function without extra swapping.
    """
    token = CancellationToken()
    recorded_profiles = []

    @idaread
    def inner_tool():
      recorded_profiles.append(("inner", sys.getprofile()))
      return "inner_done"

    @idawrite
    def outer_tool():
      recorded_profiles.append(("outer", sys.getprofile()))
      res = inner_tool.sync_call()
      recorded_profiles.append(("after_inner", sys.getprofile()))
      return f"outer_{res}"

    with mock.patch("idaapi.is_main_thread", return_value=True):
      with cancellation_profile(token):
        result = outer_tool.sync_call()
        self.assertEqual(result, "outer_inner_done")

    self.assertEqual(len(recorded_profiles), 3)
    p_outer = recorded_profiles[0][1]
    p_inner = recorded_profiles[1][1]
    p_after = recorded_profiles[2][1]

    self.assertTrue(is_ida_mcp_canceller(p_outer, token))
    self.assertIs(p_outer, p_inner)
    self.assertIs(p_outer, p_after)
    self.assertIsNone(sys.getprofile())

  def test_nested_idatool_cancels_via_outer_profile(self):
    """Verifies nested cancellation uses the outer profile hook.

    Cancellation triggered inside a child tool propagates through the
    profile hook established by the top-level tool.
    """
    token = CancellationToken()

    @idaread
    def inner_tool():
      token.cancel()
      # Trigger profile hook via function call
      len([1, 2, 3])
      return "should_not_reach"

    @idawrite
    def outer_tool():
      return inner_tool.sync_call()

    with mock.patch("idaapi.is_main_thread", return_value=True):
      with cancellation_profile(token):
        with self.assertRaises(asyncio.CancelledError):
          outer_tool.sync_call()

    self.assertIsNone(sys.getprofile())


if __name__ == "__main__":
  unittest.main()
