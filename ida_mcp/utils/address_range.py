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

import bisect


class AddressRangeManager:
  """Manages a collection of address ranges using the `bisect` module for performance.

  Assumes ranges are half-open intervals: [start, end), where `end` is
  exclusive.
  """

  def __init__(self):
    # Flattened list of bounds: [start1, end1, start2, end2, ...]
    # This allows O(log N) lookups for operations.
    self._ranges = []

  def add(self, start, end):
    """Adds a range [start, end).

    If the new range overlaps or abuts with any existing ranges, they are
    merged.
    """
    if start >= end:
      return

    # Find insertion points
    i = bisect.bisect_left(self._ranges, start)
    j = bisect.bisect_right(self._ranges, end)

    new_start = start
    if i % 2 != 0:
      # 'start' falls inside an existing range. Extend our new range to its start.
      new_start = self._ranges[i - 1]
      i -= 1

    new_end = end
    if j % 2 != 0:
      # 'end' falls inside an existing range. Extend our new range to its end.
      new_end = self._ranges[j]
      j += 1

    # Replace the affected ranges with the merged single range
    self._ranges[i:j] = [new_start, new_end]

  def erase(self, start, end):
    """Removes a range [start, end).

    Any existing ranges that overlap with this range will be modified or split.
    """
    if start >= end:
      return

    i = bisect.bisect_left(self._ranges, start)
    j = bisect.bisect_right(self._ranges, end)

    replace_with = []
    if i % 2 != 0:
      # The start of the erasure falls inside an existing interval.
      # We keep the portion of the interval before 'start'.
      replace_with.append(start)

    if j % 2 != 0:
      # The end of the erasure falls inside an existing interval.
      # We keep the portion of the interval after 'end'.
      replace_with.append(end)

    # Slice assignment automatically handles removal of fully overlapped intervals
    # and insertion of the split bounds.
    self._ranges[i:j] = replace_with

  def __len__(self):
    return len(self._ranges) // 2

  def __iter__(self):
    """Returns an iterator over the sorted, disjoint ranges.

    Yields tuples of (start, end).
    """
    it = iter(self._ranges)
    for start in it:
      yield (start, next(it))

  def __contains__(self, addr: int) -> bool:
    """Returns True if the given address falls within any managed range."""
    i = bisect.bisect_right(self._ranges, addr)
    return i % 2 != 0
