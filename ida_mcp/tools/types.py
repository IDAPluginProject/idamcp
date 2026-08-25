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


"""This module provides tools for working with types in IDA Pro."""

import re
from typing import Annotated, Any, List, Tuple

import ida_ida
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.synchronization import idaread
from ida_mcp.core.synchronization import idawrite
from ida_mcp.utils import helper
import ida_typeinf
import idaapi
from shared.rpc import ToolError
from shared.types import EnumDefinition
from shared.types import EnumMember
from shared.types import StackFrameVariable
from shared.types import StructureDefinition
from shared.types import StructureMember


@jsonrpc
@idaread
def list_enums(
    name_pattern: Annotated[
        str,
        "Optional case-insensitive regular expression pattern to match"
        ' enum names (default: "", matches all).',
    ] = "",
    include_members: Annotated[
        bool,
        "Whether to include the list of members for each enum (default: True).",
    ] = True,
) -> list[EnumDefinition]:
  """Lists all defined enums (enumerated types) in the IDA database."""
  results: list[EnumDefinition] = []
  limit = helper.get_ordinal_limit()

  regex = None
  if name_pattern:
    regex = helper.compile_regex(name_pattern, re.IGNORECASE)

  seen_names = set()

  # Iterate through numbered types (TIL)
  for ordinal in range(1, limit):
    tif = ida_typeinf.tinfo_t()
    if not tif.get_numbered_type(None, ordinal):
      continue
    if not tif.is_enum():
      continue

    type_name = str(tif.get_type_name())
    if not type_name or type_name in seen_names:
      continue

    if regex and not regex.search(type_name):
      continue

    seen_names.add(type_name)

    ei = ida_typeinf.enum_type_data_t()
    if tif.get_enum_details(ei):
      result: EnumDefinition = {
          "name": type_name,
          "member_count": len(ei),
          "size": tif.get_size(),
          "ordinal": ordinal,
      }

      if include_members:
        members: list[EnumMember] = []
        for edm in ei:
          members.append({"name": edm.name, "value": hex(edm.value)})
        if members:
          result["members"] = members

      results.append(result)

  return results


def parse_decls_safe(decls: str, hti_flags: int) -> Tuple[int, List[str]]:
  """Parses C declarations safely using official IDAPython bindings."""
  messages: list[str] = []

  # Define a callback to capture compiler error strings if supported by SWIG
  # wrapper
  def error_printer(msg: str) -> None:
    messages.append(msg)

  try:
    # In standard IDAPython, parse_decls takes a callable to print errors
    errno = ida_typeinf.parse_decls(None, decls, error_printer, hti_flags)  # type: ignore
  except Exception:  # pylint: disable=broad-exception-caught
    # Fallback to passing None for printer_t* if callable callback is not
    # supported
    try:
      errno = ida_typeinf.parse_decls(None, decls, None, hti_flags)  # type: ignore
    except Exception:  # pylint: disable=broad-exception-caught
      errno = -1
    messages = ["Parser error (detailed warnings suppressed)"]

  return errno, messages


@jsonrpc
@idawrite
def declare_type(
    c_decl: Annotated[
        str,
        (
            "C declaration of the type. Examples include: typedef int foo_t; "
            "struct bar { int a; bool b; };"
        ),
    ],
) -> str:
  """Create or update a local type from a C declaration."""
  c_decl = c_decl.strip()
  if not c_decl:
    return "C declaration can't be an empty string"

  # PT_SIL: Suppress warning dialogs
  # PT_EMPTY: Allow empty types (maybe unnecessary?)
  # PT_TYP: Print back status messages with struct tags
  flags = (
      ida_typeinf.PT_SIL
      | getattr(ida_typeinf, "PT_EMPTY", 0)
      | ida_typeinf.PT_TYP
  )
  errno, messages = parse_decls_safe(c_decl, flags)

  if messages:
    pretty_messages = "\n".join(messages)
  else:
    pretty_messages = ""
  if errno > 0:
    if pretty_messages:
      pretty_messages = f"\n\nErrors:\n{pretty_messages}"
    return (
        f"Failed to parse type:\n{c_decl}\nError Number:"
        f" {errno}{pretty_messages}"
    )
  elif pretty_messages:
    pretty_messages = f"\n\nInfo:\n{pretty_messages}"
  return f"success{pretty_messages}"


@jsonrpc
@idaread
def list_structs(
    name_pattern: Annotated[
        str,
        "Optional case-insensitive regular expression pattern to match"
        ' structure names (default: "", matches all).',
    ] = "",
) -> list[StructureDefinition]:
  """Get structures with detailed member information.

  Optionally filter by name pattern.
  """
  results: list[StructureDefinition] = []
  limit = helper.get_ordinal_limit()

  regex = None
  if name_pattern:
    regex = helper.compile_regex(name_pattern, re.IGNORECASE)

  for ordinal in range(1, limit):
    tif = ida_typeinf.tinfo_t()
    if not tif.get_numbered_type(None, ordinal):
      continue
    type_name = str(tif.get_type_name())
    if not type_name or not tif.is_udt():
      continue

    if regex and not regex.search(type_name):
      continue

    result: StructureDefinition = {
        "name": type_name,
        "type": str(tif._print()),  # pylint: disable=protected-access
        "size": tif.get_size(),
        "is_udt": True,
        "ordinal": ordinal,
        "member_count": 0,
        "udt_type": "Struct",
        "members": [],
    }

    udt_data = ida_typeinf.udt_type_data_t()
    if tif.get_udt_details(udt_data):
      result["member_count"] = udt_data.size()
      result["udt_type"] = "Union" if udt_data.is_union else "Struct"

      members: list[StructureMember] = []
      for i, member in enumerate(udt_data):
        offset = member.begin() // 8  # Convert bits to bytes
        size = member.size // 8 if member.size > 0 else member.type.get_size()
        members.append({
            "index": i,
            "name": member.name,
            "offset": offset,
            "size": size,
            "type": member.type._print(),  # pylint: disable=protected-access
        })
      if members:
        result["members"] = members

    results.append(result)

  return results


@jsonrpc
@idaread
def get_struct_at_address(
    address: Annotated[str, "Address to analyze structure at"],
    struct_name: Annotated[str, "Name of the structure"],
) -> dict[str, Any]:
  """Get structure field values at a specific address."""
  addr = helper.parse_and_check_ea(address)

  # Get structure tinfo
  tif = ida_typeinf.tinfo_t()
  if not tif.get_named_type(None, struct_name):
    raise ToolError(f"Structure '{struct_name}' not found!")

  # Get structure details
  udt_data = ida_typeinf.udt_type_data_t()
  if not tif.get_udt_details(udt_data):
    raise ToolError("Failed to get structure details!")

  result = {"struct_name": struct_name, "address": f"0x{addr:X}", "members": []}

  for member in udt_data:
    offset = member.begin() // 8
    member_addr = addr + offset
    member_type = member.type._print()  # pylint: disable=protected-access
    member_name = member.name
    member_size = member.type.get_size()

    # Try to get value based on size
    try:
      if member.type.is_ptr():
        # Pointer
        is_64bit = ida_ida.inf_is_64bit()
        if is_64bit:
          value = idaapi.get_qword(member_addr)
          value_str = f"0x{value:016X}"
        else:
          value = idaapi.get_dword(member_addr)
          value_str = f"0x{value:08X}"
      elif member_size == 1:
        value = idaapi.get_byte(member_addr)
        value_str = f"0x{value:02X} ({value})"
      elif member_size == 2:
        value = idaapi.get_word(member_addr)
        value_str = f"0x{value:04X} ({value})"
      elif member_size == 4:
        value = idaapi.get_dword(member_addr)
        value_str = f"0x{value:08X} ({value})"
      elif member_size == 8:
        value = idaapi.get_qword(member_addr)
        value_str = f"0x{value:016X} ({value})"
      else:
        # For large structures, read first few bytes
        bytes_data = []
        for i in range(min(member_size, 16)):
          try:
            byte_val = idaapi.get_byte(member_addr + i)
            bytes_data.append(f"{byte_val:02X}")
          except:
            break
        value_str = (
            f"[{' '.join(bytes_data)}{'...' if member_size > 16 else ''}]"
        )
    except:
      value_str = "<failed to read>"

    member_info = {
        "offset": f"0x{offset:08X}",
        "type": member_type,
        "name": member_name,
        "value": value_str,
    }

    result["members"].append(member_info)

  return result


def get_stack_frame_variables_internal(
    address: int, raise_error: bool
) -> list[StackFrameVariable]:
  """Retrieves the stack frame variables for a given function."""
  ida_major = helper.get_ida_version()[0]
  # TODO: IDA 8.3 does not support tif.get_type_by_tid
  if ida_major < 9:
    if raise_error:
      raise ToolError("This tool requires IDA Pro version to be >= 9.0")
    return []

  if not helper.get_func_bounds(address):
    if raise_error:
      raise ToolError(f"No function found at address {address}")
    return []

  tif = ida_typeinf.tinfo_t()
  if not helper.get_func_frame(tif, address) or not tif.is_udt():
    return []

  members: list[StackFrameVariable] = []
  udt = ida_typeinf.udt_type_data_t()
  tif.get_udt_details(udt)
  for udm in udt:
    if not udm.is_gap():
      name = udm.name
      offset = udm.offset // 8
      size = udm.size // 8
      var_type = str(udm.type)
      members.append(
          StackFrameVariable(
              name=name, offset=hex(offset), size=hex(size), type=var_type
          )
      )
  return members


@jsonrpc
@idaread
def get_stack_frame_variables(
    address: Annotated[
        str,
        (
            "Address of the disassembled function to retrieve the stack frame"
            " variables"
        ),
    ],
) -> list[StackFrameVariable]:
  """Retrieve the stack frame variables for a given function."""
  return get_stack_frame_variables_internal(
      helper.parse_and_check_ea(address), True
  )
