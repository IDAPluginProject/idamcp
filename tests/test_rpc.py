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

"""Unit tests for JSON-RPC client and server."""

import asyncio
import json
import time
import unittest
from shared.rpc import RPCClient
from shared.rpc import RPCError
from shared.rpc import RPCServer
from shared.rpc import ToolError


class TestRPC(unittest.IsolatedAsyncioTestCase):
  """Unit tests for RPCClient and RPCServer communication."""

  async def asyncSetUp(self):
    self.methods = {
        "add": lambda x, y: x + y,
        "slow_identity": self.slow_identity,
        "slow_cleanup": self.slow_cleanup,
        "raise_error": self.raise_error,
        "raise_tool_error": self.raise_tool_error,
    }
    # Set by slow_cleanup.
    self.started = asyncio.Event()
    self.cancelled = asyncio.Event()
    self.cleanup_done = asyncio.Event()
    self.cut_short = False
    self.rpc_server = RPCServer(self.methods)
    self.server = await self.rpc_server.start_tcp("127.0.0.1", 0)
    self.port = self.server.sockets[0].getsockname()[1]
    self.client = RPCClient()
    await self.client.connect_tcp("127.0.0.1", self.port)

  async def asyncTearDown(self):
    await self.client.close()
    self.server.close()
    await self.server.wait_closed()

  async def slow_identity(self, val, delay=0.5):
    """Helper method simulating a slow async RPC."""
    await asyncio.sleep(delay)
    return val

  def raise_error(self):
    """Helper method raising a test error."""
    raise ValueError("Test error")

  def raise_tool_error(self):
    """Helper method raising a tool error."""
    raise ToolError("Tool failed")

  async def slow_cleanup(self, cleanup):
    """Helper method that takes `cleanup` seconds to finish after a cancel.

    It stands in for @jsonrpc, which waits for a cancelled call's worker thread
    to stop. Records whether another cancel cut that wait short.
    """
    self.started.set()
    try:
      await asyncio.sleep(10)
    except asyncio.CancelledError:
      self.cancelled.set()
      try:
        await asyncio.sleep(cleanup)
      except asyncio.CancelledError:
        self.cut_short = True
        raise
      finally:
        self.cleanup_done.set()
      raise

  async def start_slow_cleanup(self, cleanup):
    """Calls slow_cleanup and waits until the server runs it."""
    call = asyncio.create_task(
        self.client.call("slow_cleanup", {"cleanup": cleanup})
    )
    await asyncio.wait_for(self.started.wait(), 2)
    return call

  async def cancel_call(self, call):
    """Cancels a call, which sends $/cancelRequest, and waits for the server."""
    call.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await call
    await asyncio.wait_for(self.cancelled.wait(), 2)

  async def disconnect(self):
    """Closes the client and waits until the server has handled it."""
    await self.client.close()

    async def wait_for_server():
      while self.rpc_server.active_connections:
        await asyncio.sleep(0.01)

    await asyncio.wait_for(wait_for_server(), 2)

  async def test_success_call(self):
    """Tests a successful synchronous RPC invocation."""
    res = await self.client.call("add", {"x": 1, "y": 2})
    self.assertEqual(res, 3)

  async def test_ping(self):
    """Tests ping/pong health check."""
    res = await self.client.ping()
    self.assertTrue(res)

  async def test_method_not_found(self):
    """Tests that calling an unknown method returns method not found error."""
    with self.assertRaises(RPCError) as ctx:
      await self.client.call("non_existent")
    self.assertIn("Method not found", str(ctx.exception))

  async def test_server_error(self):
    """Tests that server-side exceptions are converted to RPCError."""
    with self.assertRaises(RPCError) as ctx:
      await self.client.call("raise_error")
    self.assertIn("Test error", str(ctx.exception))

  async def test_tool_error_is_reported_without_traceback(self):
    """Tests that a ToolError is sent as -32001, logged without a traceback."""
    with self.assertLogs("shared.rpc", level="WARNING") as logs:
      with self.assertRaises(RPCError) as ctx:
        await self.client.call("raise_tool_error")
    self.assertEqual(str(ctx.exception), "Tool failed")
    self.assertEqual(ctx.exception.data, -32001)
    self.assertEqual([record.levelname for record in logs.records], ["WARNING"])
    self.assertIsNone(logs.records[0].exc_info)

  async def test_connection_closed_by_server(self):
    """Tests handling when server closes connection unexpectedly."""
    # Start a slow call
    task = asyncio.create_task(
        self.client.call("slow_identity", {"val": 42, "delay": 2.0})
    )
    await asyncio.sleep(0.1)  # Ensure request is sent and server is processing

    # Force close all server connections
    for transport in list(self.rpc_server.active_connections):
      transport.close()

    # The client call should fail with connection closed
    with self.assertRaises(RPCError) as ctx:
      await task
    self.assertIn("Connection closed", str(ctx.exception))

    # Subsequent calls should fail fast
    with self.assertRaises(RPCError) as ctx:
      await self.client.call("add", {"x": 1, "y": 2})
    self.assertIn("Connection is closed", str(ctx.exception))

  async def test_client_cancellation(self):
    """Tests that client cancellation sends $/cancelRequest to server."""
    # Start a slow call
    task = asyncio.create_task(
        self.client.call("slow_identity", {"val": 42, "delay": 2.0})
    )
    await asyncio.sleep(0.1)  # Ensure request is sent

    # Cancel the client task
    task.cancel()

    with self.assertRaises(asyncio.CancelledError):
      await task

    # Verify the server cancelled the task
    await asyncio.sleep(0.2)

    # Get the server transport
    self.assertEqual(len(self.rpc_server.active_connections), 1)
    transport = list(self.rpc_server.active_connections)[0]

    # Running tasks for this transport should be empty
    running_tasks = self.rpc_server.running_tasks.get(transport, {})
    self.assertEqual(len(running_tasks), 0)

  async def test_disconnect_does_not_cut_a_cancelled_call_short(self):
    """Tests that a disconnect doesn't cancel a call that is already cancelled.

    A second cancel would make @jsonrpc stop waiting for the call's worker
    thread, which would keep running.
    """
    call = await self.start_slow_cleanup(cleanup=0.2)
    await self.cancel_call(call)
    await self.disconnect()
    await asyncio.wait_for(self.cleanup_done.wait(), 2)
    self.assertFalse(self.cut_short)

  async def test_repeated_cancel_request_is_ignored(self):
    """Tests that a second $/cancelRequest for a call is ignored."""
    call = await self.start_slow_cleanup(cleanup=0.2)
    [req_id] = self.client.pending_requests
    await self.cancel_call(call)
    request = {
        "jsonrpc": "2.0",
        "method": "$/cancelRequest",
        "params": {"id": req_id},
    }
    self.client.writer.write(json.dumps(request).encode("utf-8") + b"\n")
    await self.client.writer.drain()
    await asyncio.wait_for(self.cleanup_done.wait(), 2)
    self.assertFalse(self.cut_short)

  async def test_close_waits_for_cancelled_tasks(self):
    """Tests that close() lets a cancelled task finish."""
    call = await self.start_slow_cleanup(cleanup=0.2)
    await asyncio.wait_for(self.rpc_server.close(), 5)
    self.assertTrue(self.cleanup_done.is_set())
    self.assertFalse(self.cut_short)
    await asyncio.gather(call, return_exceptions=True)

  async def test_shutdown_grace_default_and_override(self):
    """Tests the default grace period, and setting it per server."""
    self.assertEqual(self.rpc_server.shutdown_grace, 2.0)
    self.assertEqual(RPCServer({}, shutdown_grace=0.5).shutdown_grace, 0.5)

  async def test_close_cancels_again_after_grace_period(self):
    """Tests that close() cancels a task again when the grace period ends."""
    self.rpc_server.shutdown_grace = 0.2
    call = await self.start_slow_cleanup(cleanup=10)
    start = time.monotonic()
    await asyncio.wait_for(self.rpc_server.close(), 5)
    elapsed = time.monotonic() - start
    self.assertTrue(self.cut_short)
    self.assertGreater(elapsed, 0.15)
    self.assertLess(elapsed, 1.5)
    await asyncio.gather(call, return_exceptions=True)

  async def test_close_includes_tasks_whose_client_disconnected(self):
    """Tests that close() also handles tasks whose connection has closed."""
    self.rpc_server.shutdown_grace = 0.2
    call = await self.start_slow_cleanup(cleanup=10)
    await self.cancel_call(call)
    await self.disconnect()
    self.assertFalse(self.cut_short)
    await asyncio.wait_for(self.rpc_server.close(), 5)
    self.assertTrue(self.cut_short)

  async def test_finished_tasks_are_forgotten(self):
    """Tests that the server stops tracking tasks once they finish."""
    self.assertEqual(await self.client.call("add", {"x": 1, "y": 2}), 3)
    call = await self.start_slow_cleanup(cleanup=0)
    await self.cancel_call(call)
    await asyncio.wait_for(self.cleanup_done.wait(), 2)
    await asyncio.sleep(0.1)  # Lets the finished tasks' callbacks run.
    # pylint: disable=protected-access
    self.assertEqual(self.rpc_server._tasks, set())
    self.assertEqual(self.rpc_server._cancelled, set())


if __name__ == "__main__":
  unittest.main()
