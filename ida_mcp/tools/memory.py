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


"""Memory reading and writing tools."""

from typing import Annotated, List
import ida_bytes
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.synchronization import idaread
from ida_mcp.utils import helper
from ida_mcp.utils import hexdump as utils_hexdump
import ida_nalt
import ida_typeinf
import idaapi
from shared.rpc import ToolError
from shared.types import BatchResponseItem, ReadDataRequest


def get_global_variable_value_internal(ea: int) -> str:
  """Internal helper to get the value of a global variable.

  Args:
    ea: The effective address of the variable.

  Returns:
    The string representation of the variable's value.
  """
  if not idaapi.is_loaded(ea):
    raise ToolError(f"The specified address {ea} is not initialized.")

  # Get the type information for the variable
  tif = ida_typeinf.tinfo_t()
  if not ida_nalt.get_tinfo(tif, ea):
    # No type info, maybe we can figure out its size by its name
    if not ida_bytes.has_any_name(idaapi.get_flags(ea)):
      raise ToolError(
          f"Failed to get type information for variable at {ea:#x}, it has no"
          " name"
      )

    size = ida_bytes.get_item_size(ea)
    if size == 0:
      raise ToolError(
          f"Failed to get type information for variable at {ea:#x},"
          " ida_bytes.get_item_size returns 0"
      )
  else:
    # Determine the size of the variable
    size = tif.get_size()
  # Read the value based on the size
  match size:
    case 0:
      if tif.is_array() and tif.get_array_element().is_decl_char():
        return_string = (
            idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8").strip()
        )
        return f'"{return_string}"'
    case 1:
      return hex(ida_bytes.get_byte(ea))
    case 2:
      return hex(ida_bytes.get_word(ea))
    case 4:
      return hex(ida_bytes.get_dword(ea))
    case 8:
      return hex(ida_bytes.get_qword(ea))
  # For other sizes, return the raw bytes
  return " ".join(hex(x) for x in ida_bytes.get_bytes(ea, size))


@jsonrpc
@idaread
def get_global_variable_value_by_name(
    reqs: Annotated[List[str], "List of names of global variables"],
) -> List[BatchResponseItem]:
  """Read global variables' values (if known at compile-time).

  Prefer this function over the `read_*` functions.
  """
  results = []
  for name in reqs:
    ea = idaapi.get_name_ea(idaapi.BADADDR, name)
    if ea == idaapi.BADADDR:
      results.append(
          BatchResponseItem(
              success=False, error=f"Global variable {name} not found"
          )
      )
      continue

    try:
      val = get_global_variable_value_internal(ea)
      results.append(BatchResponseItem(success=True, value=val))
    except Exception as e:
      results.append(BatchResponseItem(success=False, error=str(e)))

  return results


@jsonrpc
@idaread
def get_global_variable_value_at_address(
    reqs: Annotated[List[str], "List of addresses of global variables"],
) -> List[BatchResponseItem]:
  """Read global variables' values by their addresses (if known at compile-time).

  Prefer this function over the `read_*` functions.
  """
  results = []
  for address in reqs:
    try:
      ea = helper.parse_and_check_ea(address)
    except Exception as e:
      results.append(
          BatchResponseItem(
              success=False, error=f"Failed to parse address '{address}': {e}"
          )
      )
      continue

    try:
      val = get_global_variable_value_internal(ea)
      results.append(BatchResponseItem(success=True, value=val))
    except Exception as e:
      results.append(
          BatchResponseItem(
              success=False, error=f"Error reading variable at {address}: {e}"
          )
      )
  return results


@jsonrpc
@idaread
def read_data(
    reqs: Annotated[List[ReadDataRequest], "List of read data requests"],
) -> List[BatchResponseItem]:
  """Read formatted data from memory at given addresses."""
  results = []
  for req in reqs:
    try:
      ea = helper.parse_and_check_ea(req.address)
    except Exception as e:
      results.append(
          BatchResponseItem(
              success=False,
              error=f"Failed to parse address '{req.address}': {e}",
          )
      )
      continue

    if not idaapi.is_loaded(ea):
      results.append(
          BatchResponseItem(
              success=False,
              error=f"The specified address {req.address} is not initialized.",
          )
      )
      continue

    try:
      match req.data_type:
        case "byte":
          val = hex(ida_bytes.get_wide_byte(ea))
        case "word":
          val = hex(ida_bytes.get_wide_word(ea))
        case "dword":
          val = hex(ida_bytes.get_wide_dword(ea))
        case "qword":
          val = hex(ida_bytes.get_qword(ea))
        case "string":
          s = idaapi.get_strlit_contents(ea, -1, 0)
          if s is None:
            results.append(
                BatchResponseItem(
                    success=False,
                    error=(
                        f"idaapi.get_strlit_contents({ea:#x}, -1, 0) returned"
                        " None"
                    ),
                )
            )
            continue
          val = s.decode("utf-8")
        case "bytes":
          val = " ".join(f"{x:#02x}" for x in ida_bytes.get_bytes(ea, req.size))
        case _:
          results.append(
              BatchResponseItem(
                  success=False, error=f"Unsupported data type: {req.data_type}"
              )
          )
          continue
      results.append(BatchResponseItem(success=True, value=val))
    except Exception as e:
      results.append(
          BatchResponseItem(
              success=False,
              error=f"Error reading {req.data_type} at {req.address}: {e}",
          )
      )
  return results


@jsonrpc
@idaread
def hexdump(
    address: Annotated[str, "Address (e.g., '0x400000') to start the hexdump"],
    length: Annotated[
        int, "Length of the memory region to dump in bytes, max 0x1000 per call"
    ],
) -> str:
  """Get a formatted hexadecimal dump of memory at the specified address.

  Each request is limited to a maximum of 0x1000 bytes. This tool is useful for
  examining raw memory contents, such as unknown data structures, encrypted
  payloads, or inline strings.
  """
  ea = helper.parse_and_check_ea(address)
  if not idaapi.is_loaded(ea):
    raise ToolError(
        f"The specified address {address} is not initialized.",
    )

  data = idaapi.get_bytes(ea, min(length, 0x1000), 0)
  if data is None:
    raise ToolError(
        f"Memory read failed: idaapi.get_bytes({address},"
        f" {length:#x}) returned None. This indicates the"
        " memory range is either invalid, unmapped, or contains"
        " uninitialized byte(s)."
    )
  return utils_hexdump.hexdump(data, address=ea)
