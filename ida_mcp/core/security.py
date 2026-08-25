# Copyright (c) 2026 Google LLC
# Copyright (c) 2025 Duncan Ogilvie
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

"""Manages security settings for the IDA MCP plugin."""

import json
import logging
from typing import Any, List, Set
from ida_mcp.core.synchronization import idaread
from ida_mcp.core.synchronization import idawrite
import ida_netnode

logger = logging.getLogger(__name__)


class SecurityManager:
  """Handles loading, saving, and checking of security settings."""

  def __init__(self):
    self.enable_all_unsafe_tools = False
    self.enabled_unsafe_tools: Set[str] = set()

  def load_defaults(self, config: dict[str, Any]):
    """Load defaults from global config file."""
    self.enable_all_unsafe_tools = config.get("enable_all_unsafe_tools", False)
    # Continue to load the list even if self.enable_all_unsafe_tools is true,
    # this is to enable toggling the global switch on the fly.
    self.enabled_unsafe_tools.update(config.get("enabled_unsafe_tools", []))

  @idaread
  def load_from_netnode(self):
    """Load persistent settings from IDA netnode."""
    try:
      if not ida_netnode.netnode.exist("$IDAMCP_SECURITY"):
        return
      # Create or get netnode
      node = ida_netnode.netnode("$IDAMCP_SECURITY", 0, True)
      if not node.value_exists():
        return
      # Read value (returns bytes or None)
      blob = node.getblob(0, "G")
      if blob:
        try:
          data = json.loads(blob)
          self.enable_all_unsafe_tools = data.get(
              "enable_all_unsafe_tools", False
          )
          self.enabled_unsafe_tools = set(data.get("enabled_unsafe_tools", []))
          logger.info("Loaded security settings from netnode")
        except json.JSONDecodeError:
          logger.error("Failed to decode security settings from netnode")
    except Exception as e:  # type: ignore
      logger.error("Error loading security settings from netnode: %s", e)

  @idawrite
  def save_to_netnode(self):
    """Save current settings to IDA netnode."""

    try:
      node = ida_netnode.netnode("$IDAMCP_SECURITY", 0, True)
      data = {
          "enable_all_unsafe_tools": self.enable_all_unsafe_tools,
          "enabled_unsafe_tools": list(self.enabled_unsafe_tools),
      }
      blob = json.dumps(data).encode("utf-8")
      node.setblob(blob, 0, "G")
      logger.info("Saved security settings to netnode")
    except Exception as e:  # type: ignore
      logger.error("Error saving security settings to netnode: %s", e)

  def is_allowed(self, tool_name: str, is_unsafe: bool) -> bool:
    if not is_unsafe:
      return True
    if self.enable_all_unsafe_tools:
      return True
    return tool_name in self.enabled_unsafe_tools

  def update(self, enable_all: bool, enabled_tools: List[str]):
    self.enable_all_unsafe_tools = enable_all
    self.enabled_unsafe_tools = set(enabled_tools)


security_manager = SecurityManager()
