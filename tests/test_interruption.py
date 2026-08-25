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
from ida_mcp.core.decorators import cancellation_token_var
from ida_mcp.core.decorators import CancellationToken
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.decorators import register_cancel_callback
from ida_mcp.core.synchronization import IDASafety
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
    """Tests that sync_wrapper raises before execution if token is cancelled."""
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


if __name__ == "__main__":
  unittest.main()
