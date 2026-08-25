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

"""Module for registering and managing JSON-RPC methods."""

import re
from typing import Callable
from shared.config import load_config


class RPCRegistry:
  """A registry for JSON-RPC methods."""

  def __init__(self):
    self.methods = set()
    self.unsafe: set[str] = set()
    self._config = None

  def register(self, func: Callable) -> Callable:
    """Registers a function as a JSON-RPC method."""
    if self._config is None:
      try:
        self._config = load_config()
      except Exception:  # pylint: disable=broad-exception-caught
        self._config = {}

    disabled_tools = self._config.get("disabled_tools", [])
    for pattern in disabled_tools:
      try:
        if re.search(pattern, func.__name__, re.IGNORECASE):
          return func
      except Exception:  # pylint: disable=broad-exception-caught
        pass

    self.methods.add(func)
    if getattr(func, "unsafe", False):
      self.unsafe.add(func.__name__)
    return func


rpc_registry = RPCRegistry()
