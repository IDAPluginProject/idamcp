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

"""Cache utilities for the IDA MCP plugin."""

import collections
from collections import abc
from typing import Any, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class IteratorCache(abc.MutableMapping[K, abc.Iterator[V]]):
  """An LRU cache for iterators.

  This class implements the MutableMapping interface and uses an OrderedDict
  to manage eviction of the least recently used items when the capacity is
  reached.
  """

  def __init__(self, capacity: int = 128) -> None:
    """Initialize the cache.

    Args:
      capacity: The maximum number of items to hold in the cache. Defaults to
        128.
    """
    self._capacity = capacity
    self._cache: collections.OrderedDict[K, abc.Iterator[V]] = (
        collections.OrderedDict()
    )

  def __hash__(self) -> int:
    return id(self)

  def __eq__(self, other: Any) -> bool:
    return self is other

  def __getitem__(self, key: K) -> abc.Iterator[V]:
    """Retrieve an item from the cache.

    Accessing an item moves it to the most recently used end.

    Args:
      key: The key to look up.

    Returns:
      The iterator associated with the key.

    Raises:
      KeyError: If the key is not in the cache.
    """
    if key not in self._cache:
      raise KeyError(key)
    self._cache.move_to_end(key)
    return self._cache[key]

  def __setitem__(self, key: K, value: abc.Iterator[V]) -> None:
    """Add or update an item in the cache.

    If the key exists, it is moved to the most recently used end.
    If the cache is full, the least recently used item (FIFO) is evicted.

    Args:
      key: The key to set.
      value: The iterator to store.
    """
    if key in self._cache:
      self._cache.move_to_end(key)
    self._cache[key] = value
    if len(self._cache) > self._capacity:
      self._cache.popitem(last=False)

  def __delitem__(self, key: K) -> None:
    """Remove an item from the cache.

    Args:
      key: The key to remove.
    """
    del self._cache[key]

  def __iter__(self) -> abc.Iterator[K]:
    """Iterate over the keys in the cache.

    Returns:
      An iterator over the keys.
    """
    return iter(self._cache)

  def __len__(self) -> int:
    """Return the number of items in the cache.

    Returns:
      The number of items in the cache.
    """
    return len(self._cache)

  def pop(self, key: K, default: Any = ...) -> abc.Iterator[V] | Any:
    """Remove and return an item from the cache.

    Args:
      key: The key to remove.
      default: value to return if key is not found.

    Returns:
      The iterator associated with the key, or the default value.
    """
    # We use the internal _cache.pop to avoid calling __getitem__
    # (which would update LRU unnecessarily before delete)
    if default is ...:
      return self._cache.pop(key)
    return self._cache.pop(key, default)

  def clear(self) -> None:
    """Clear all items in the cache."""
    self._cache.clear()
