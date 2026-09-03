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

"""Unit tests for HeadlessManager coldest eviction policy and forwarder."""

import asyncio
import unittest
from unittest import mock

from gateway.forward import _global_client_state
from gateway.forward import _global_clients
from gateway.forward import _global_database_id_to_pid
from gateway.forward import _headless_manager
from gateway.forward import forward_to
from gateway.forward import HeadlessManager


class TestHeadlessManager(unittest.IsolatedAsyncioTestCase):
  """Tests for HeadlessManager recency tracking and coldest eviction."""

  async def asyncSetUp(self):
    self.manager = HeadlessManager(max_instances=3)
    _global_client_state.clear()
    _global_database_id_to_pid.clear()

  async def asyncTearDown(self):
    _global_client_state.clear()
    _global_database_id_to_pid.clear()

  def test_touch_updates_order(self):
    """Test that touching an instance moves it to MRU."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)
    self.manager.register("db3", 1003)

    self.assertEqual(list(self.manager.lru_queue), ["db1", "db2", "db3"])

    # Touch the oldest element db1
    self.manager.touch("db1")
    self.assertEqual(list(self.manager.lru_queue), ["db2", "db3", "db1"])

  def test_touch_nonexistent_is_noop(self):
    """Test that touching an unknown database ID is a safe no-op."""
    self.manager.register("db1", 1001)
    self.manager.touch("nonexistent")
    self.assertEqual(list(self.manager.lru_queue), ["db1"])

  def test_register_reorders_existing_to_mru(self):
    """Test that re-registering an existing instance moves it to MRU."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)
    self.assertEqual(list(self.manager.lru_queue), ["db1", "db2"])

    self.manager.register("db1", 1001)
    self.assertEqual(list(self.manager.lru_queue), ["db2", "db1"])

  async def test_unregister_removes_from_queue(self):
    """Test that unregistering removes an instance from queue."""
    self.manager.register("db1", 1001)
    self.assertIn("db1", self.manager.lru_queue)

    with mock.patch("gateway.forward._is_process_running", return_value=False):
      await self.manager.unregister("db1")

    self.assertNotIn("db1", self.manager.lru_queue)

  async def test_evict_coldest_selects_lru(self):
    """Test that evict_coldest chooses the least recently used instance."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)
    self.manager.register("db3", 1003)

    # db1 is touched, so queue is: db2, db3, db1 (db2 is coldest)
    self.manager.touch("db1")

    close_calls = []

    async def fake_close(db_id):
      close_calls.append(db_id)
      self.manager.lru_queue.remove(db_id)

    with mock.patch.object(self.manager, "close", side_effect=fake_close):
      await self.manager.evict_coldest()

    self.assertEqual(close_calls, ["db2"])
    self.assertEqual(list(self.manager.lru_queue), ["db3", "db1"])

  async def test_evict_coldest_skips_busy_instances(self):
    """Test that evict_coldest prioritizes idle instances over busy ones."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)
    self.manager.register("db3", 1003)

    # db1 is coldest, but mark it busy with ongoing calls
    _global_client_state["db1"].number_of_ongoing_calls = 2
    _global_client_state["db2"].number_of_ongoing_calls = 0
    _global_client_state["db3"].number_of_ongoing_calls = 0

    close_calls = []

    async def fake_close(db_id):
      close_calls.append(db_id)
      self.manager.lru_queue.remove(db_id)

    with mock.patch.object(self.manager, "close", side_effect=fake_close):
      await self.manager.evict_coldest()

    # db2 is the coldest idle instance, so it should be evicted instead of db1
    self.assertEqual(close_calls, ["db2"])
    self.assertEqual(list(self.manager.lru_queue), ["db1", "db3"])

  async def test_evict_coldest_prioritizes_broken_instances(self):
    """Test that evict_coldest prioritizes broken or closed instances."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)
    self.manager.register("db3", 1003)

    # db3 is newest/hottest, but marked broken
    _global_client_state["db3"].is_broken = True

    close_calls = []

    async def fake_close(db_id):
      close_calls.append(db_id)
      self.manager.lru_queue.remove(db_id)

    with mock.patch.object(self.manager, "close", side_effect=fake_close):
      await self.manager.evict_coldest()

    # db3 should be evicted first due to broken state
    self.assertEqual(close_calls, ["db3"])
    self.assertEqual(list(self.manager.lru_queue), ["db1", "db2"])

  async def test_evict_coldest_all_busy_fallback(self):
    """Test that if all instances are busy, fallback to absolute coldest."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)

    _global_client_state["db1"].number_of_ongoing_calls = 1
    _global_client_state["db2"].number_of_ongoing_calls = 1

    close_calls = []

    async def fake_close(db_id):
      close_calls.append(db_id)
      self.manager.lru_queue.remove(db_id)

    with mock.patch.object(self.manager, "close", side_effect=fake_close):
      await self.manager.evict_coldest()

    self.assertEqual(close_calls, ["db1"])
    self.assertEqual(list(self.manager.lru_queue), ["db2"])

  async def test_evict_coldest_empty_queue_safe(self):
    """Test that evict_coldest on empty queue returns safely."""
    await self.manager.evict_coldest()
    self.assertEqual(len(self.manager.lru_queue), 0)

  async def test_forward_to_touches_headless_manager(self):
    """Test that forward_to touches the target database instance."""
    mock_client = mock.AsyncMock()
    mock_client.call.return_value = {"status": "ok"}
    _global_clients["test_db"] = mock_client

    with mock.patch.object(_headless_manager, "touch") as mock_touch:
      result = await forward_to("test_db", "ping", {})
      self.assertEqual(result, {"status": "ok"})
      # Should touch at start and in finally
      self.assertEqual(mock_touch.call_count, 2)
      mock_touch.assert_called_with("test_db")
