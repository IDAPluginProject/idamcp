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

import unittest
from ida_mcp.utils.address_range import AddressRangeManager


class TestAddressRangeManager(unittest.TestCase):

  def test_add_non_overlapping(self):
    arm = AddressRangeManager()
    arm.add(0, 5)
    arm.add(10, 15)
    self.assertEqual(list(arm), [(0, 5), (10, 15)])

  def test_add_abutting(self):
    arm = AddressRangeManager()
    arm.add(0, 5)
    arm.add(5, 10)
    self.assertEqual(list(arm), [(0, 10)])

  def test_add_abutting_reverse(self):
    arm = AddressRangeManager()
    arm.add(5, 10)
    arm.add(0, 5)
    self.assertEqual(list(arm), [(0, 10)])

  def test_add_overlapping(self):
    arm = AddressRangeManager()
    arm.add(0, 5)
    arm.add(3, 8)
    self.assertEqual(list(arm), [(0, 8)])

  def test_add_subset(self):
    arm = AddressRangeManager()
    arm.add(0, 10)
    arm.add(3, 8)
    self.assertEqual(list(arm), [(0, 10)])

  def test_add_superset(self):
    arm = AddressRangeManager()
    arm.add(3, 8)
    arm.add(0, 10)
    self.assertEqual(list(arm), [(0, 10)])

  def test_add_multiple_merges(self):
    arm = AddressRangeManager()
    arm.add(0, 5)
    arm.add(10, 15)
    arm.add(20, 25)
    # Add range overlapping multiple existing disjoint ranges
    arm.add(4, 21)
    self.assertEqual(list(arm), [(0, 25)])

  def test_erase_non_overlapping(self):
    arm = AddressRangeManager()
    arm.add(0, 10)
    arm.erase(15, 20)
    self.assertEqual(list(arm), [(0, 10)])

  def test_erase_partial_start(self):
    arm = AddressRangeManager()
    arm.add(5, 15)
    arm.erase(0, 10)
    self.assertEqual(list(arm), [(10, 15)])

  def test_erase_partial_end(self):
    arm = AddressRangeManager()
    arm.add(5, 15)
    arm.erase(10, 20)
    self.assertEqual(list(arm), [(5, 10)])

  def test_erase_middle_split(self):
    arm = AddressRangeManager()
    arm.add(0, 20)
    arm.erase(5, 15)
    self.assertEqual(list(arm), [(0, 5), (15, 20)])

  def test_erase_superset(self):
    arm = AddressRangeManager()
    arm.add(5, 15)
    arm.erase(0, 20)
    self.assertEqual(list(arm), [])

  def test_erase_multiple_ranges(self):
    arm = AddressRangeManager()
    arm.add(0, 10)
    arm.add(20, 30)
    arm.add(40, 50)
    arm.erase(5, 45)  # Erase partial start, whole middle, and partial end
    self.assertEqual(list(arm), [(0, 5), (45, 50)])

  def test_invalid_ranges(self):
    arm = AddressRangeManager()
    arm.add(10, 5)  # start > end, should do nothing
    self.assertEqual(list(arm), [])

    arm.add(5, 5)  # start == end, should do nothing
    self.assertEqual(list(arm), [])

    arm.add(0, 10)
    arm.erase(8, 2)  # start > end, erase nothing
    self.assertEqual(list(arm), [(0, 10)])

  def test_complex_operations(self):
    arm = AddressRangeManager()
    arm.add(10, 20)
    arm.add(30, 40)
    self.assertEqual(list(arm), [(10, 20), (30, 40)])

    arm.add(15, 35)  # Merges both
    self.assertEqual(list(arm), [(10, 40)])

    arm.erase(20, 30)  # Splits
    self.assertEqual(list(arm), [(10, 20), (30, 40)])

    arm.erase(10, 40)  # Erases everything
    self.assertEqual(list(arm), [])


if __name__ == '__main__':
  unittest.main()
