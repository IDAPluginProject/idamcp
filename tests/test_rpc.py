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
import unittest
from shared.rpc import RPCClient
from shared.rpc import RPCError
from shared.rpc import RPCServer


class TestRPC(unittest.IsolatedAsyncioTestCase):
  """Unit tests for RPCClient and RPCServer communication."""

  async def asyncSetUp(self):
    self.methods = {
        "add": lambda x, y: x + y,
        "slow_identity": self.slow_identity,
        "raise_error": self.raise_error,
    }
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


if __name__ == "__main__":
  unittest.main()
