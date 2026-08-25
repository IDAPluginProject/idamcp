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


"""Debugger tools for IDA Pro."""

import os
from typing import Annotated
import ida_dbg
import ida_entry
import ida_idaapi
import ida_idd
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.decorators import unsafe
from ida_mcp.core.synchronization import idaread
from ida_mcp.utils import helper
import ida_name
import idaapi
from shared.rpc import ToolError
from shared.types import Breakpoint
from shared.types import RegisterValue
from shared.types import ThreadRegisters


def dbg_ensure_running() -> "ida_idd.debugger_t":
  dbg = ida_idd.get_dbg()
  if not dbg or ida_dbg.get_ip_val() is None:
    raise ToolError("Debugger not running")
  return dbg


def _get_registers_for_thread(
    dbg: "ida_idd.debugger_t", tid: int
) -> ThreadRegisters:
  """Helper to get registers for a specific thread."""
  regs = []
  regvals: ida_idd.regvals_t = ida_dbg.get_reg_vals(tid)
  for reg_index, rv in enumerate(regvals):
    rv: ida_idd.regval_t
    reg_info = dbg.regs(reg_index)

    # NOTE: Apparently this can fail under some circumstances
    try:
      reg_value = rv.pyval(reg_info.dtype)
    except ValueError:
      reg_value = ida_idaapi.BADADDR

    if isinstance(reg_value, int):
      reg_value = hex(reg_value)
    elif isinstance(reg_value, bytes):
      reg_value = reg_value.hex(" ")
    else:
      reg_value = str(reg_value)
    regs.append(
        RegisterValue(
            name=reg_info.name,
            value=reg_value,
        )
    )
  return ThreadRegisters(
      thread_id=tid,
      registers=regs,
  )


def _get_registers_specific_for_thread(
    dbg: "ida_idd.debugger_t", tid: int, register_names: list[str]
) -> ThreadRegisters:
  """Helper to get specific registers for a given thread."""
  all_registers = _get_registers_for_thread(dbg, tid)
  specific_registers = [
      reg for reg in all_registers["registers"] if reg["name"] in register_names
  ]
  return ThreadRegisters(
      thread_id=tid,
      registers=specific_registers,
  )


@jsonrpc
@idaread
@unsafe
def dbg_get_all_registers_for_all_threads() -> list[ThreadRegisters]:
  """Get all registers and their values.

  This function is only available when debugging.
  """
  result: list[ThreadRegisters] = []
  dbg = dbg_ensure_running()
  for thread_index in range(ida_dbg.get_thread_qty()):
    tid = ida_dbg.getn_thread(thread_index)
    result.append(_get_registers_for_thread(dbg, tid))
  return result


@jsonrpc
@idaread
@unsafe
def dbg_get_all_registers_for_thread(
    thread_id: Annotated[int, "ID of the thread to get registers for"],
) -> ThreadRegisters:
  """Get registers and their values for a specific thread."""
  dbg = dbg_ensure_running()
  if thread_id not in [
      ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())
  ]:
    raise ToolError(f"Thread with ID {thread_id} not found")
  return _get_registers_for_thread(dbg, thread_id)


@jsonrpc
@idaread
@unsafe
def dbg_get_all_registers_for_current_thread() -> ThreadRegisters:
  """Get registers for the current thread."""
  dbg = dbg_ensure_running()
  tid = ida_dbg.get_current_thread()
  return _get_registers_for_thread(dbg, tid)


@jsonrpc
@idaread
@unsafe
def dbg_get_registers_for_thread(
    thread_id: Annotated[int, "ID of the thread to get specific registers for"],
    register_names: Annotated[
        str, "A comma-separated list of register names to retrieve"
    ],
) -> ThreadRegisters:
  """Get specific registers and their values for a given thread."""
  dbg = dbg_ensure_running()
  if thread_id not in [
      ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())
  ]:
    raise ToolError(f"Thread with ID {thread_id} not found")
  names = [name.strip() for name in register_names.split(",")]
  return _get_registers_specific_for_thread(dbg, thread_id, names)


@jsonrpc
@idaread
@unsafe
def dbg_get_registers_for_current_thread(
    register_names: Annotated[
        str, "A comma-separated list of register names to retrieve"
    ],
) -> ThreadRegisters:
  """Get specific registers for the thread currently paused in the debugger."""
  dbg = dbg_ensure_running()
  tid = ida_dbg.get_current_thread()
  names = [name.strip() for name in register_names.split(",")]
  return _get_registers_specific_for_thread(dbg, tid, names)


@jsonrpc
@idaread
@unsafe
def dbg_get_call_stack() -> list[dict[str, str]]:
  """Get the current call stack."""
  callstack = []
  try:
    tid = ida_dbg.get_current_thread()
    trace = ida_idd.call_stack_t()

    if not ida_dbg.collect_stack_trace(tid, trace):
      return []
    for frame in trace:
      frame_info = {
          "address": hex(frame.callea),
      }
      try:
        module_info = ida_idd.modinfo_t()
        if ida_dbg.get_module_info(frame.callea, module_info):
          frame_info["module"] = os.path.basename(module_info.name)
        else:
          frame_info["module"] = "<unknown>"

        name = (
            ida_name.get_nice_colored_name(
                frame.callea,
                ida_name.GNCN_NOCOLOR
                | ida_name.GNCN_NOLABEL
                | ida_name.GNCN_NOSEG
                | ida_name.GNCN_PREFDBG,
            )
            or "<unnamed>"
        )
        frame_info["symbol"] = name

      except Exception as e:
        frame_info["module"] = "<error>"
        frame_info["symbol"] = str(e)

      callstack.append(frame_info)

  except Exception:
    pass
  return callstack


def list_breakpoints():
  """Returns a list of all breakpoints."""
  breakpoints: list[Breakpoint] = []
  for i in range(ida_dbg.get_bpt_qty()):
    bpt = ida_dbg.bpt_t()
    if ida_dbg.getn_bpt(i, bpt):
      bp = Breakpoint(
          ea=hex(bpt.ea),
          enabled=bpt.flags & ida_dbg.BPT_ENABLED,
      )
      if bpt.condition is not None:
        bp["condition"] = str(bpt.condition)

      breakpoints.append(bp)

  return breakpoints


@jsonrpc
@idaread
@unsafe
def dbg_list_breakpoints():
  """List all breakpoints in the program."""
  return list_breakpoints()


@jsonrpc
@idaread
@unsafe
def dbg_start_process():
  """Start the debugger, returns the current instruction pointer."""

  if len(list_breakpoints()) == 0:
    for i in range(ida_entry.get_entry_qty()):
      ordinal = ida_entry.get_entry_ordinal(i)
      address = ida_entry.get_entry(ordinal)
      if address != ida_idaapi.BADADDR:
        ida_dbg.add_bpt(address, 0, idaapi.BPT_SOFT)

  if idaapi.start_process("", "", "") == 1:
    ip = ida_dbg.get_ip_val()
    if ip is not None:
      return hex(ip)
  raise ToolError(
      "Failed to start debugger (did the user configure the debugger manually"
      " one time?)"
  )


@jsonrpc
@idaread
@unsafe
def dbg_exit_process():
  """Exit the debugger."""
  dbg_ensure_running()
  if idaapi.exit_process():
    return
  raise ToolError("Failed to exit debugger")


@jsonrpc
@idaread
@unsafe
def dbg_continue_process() -> str:
  """Continue the debugger, returns the current instruction pointer."""
  dbg_ensure_running()
  if idaapi.continue_process():
    ip = ida_dbg.get_ip_val()
    if ip is not None:
      return hex(ip)
  raise ToolError("Failed to continue debugger")


@jsonrpc
@idaread
@unsafe
def dbg_run_to(
    address: Annotated[str, "Run the debugger to the specified address"],
):
  """Run the debugger to the specified address."""
  dbg_ensure_running()
  ea = helper.parse_int(address)
  if idaapi.run_to(ea):
    ip = ida_dbg.get_ip_val()
    if ip is not None:
      return hex(ip)
  raise ToolError(f"Failed to run to address {ea:#x}")


@jsonrpc
@idaread
@unsafe
def dbg_set_breakpoint(
    address: Annotated[str, "Set a breakpoint at the specified address"],
):
  """Set a breakpoint at the specified address."""
  ea = helper.parse_int(address)
  if idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT):
    return f"Breakpoint set at {ea:#x}"
  breakpoints = list_breakpoints()
  for bpt in breakpoints:
    if bpt["ea"] == hex(ea):
      return
  raise ToolError(f"Failed to set breakpoint at address {ea:#x}")


@jsonrpc
@idaread
@unsafe
def dbg_step_into():
  """Step into the current instruction."""
  dbg_ensure_running()
  if idaapi.step_into():
    ip = ida_dbg.get_ip_val()
    if ip is not None:
      return hex(ip)
  raise ToolError("Failed to step into")


@jsonrpc
@idaread
@unsafe
def dbg_step_over():
  """Step over the current instruction."""
  dbg_ensure_running()
  if idaapi.step_over():
    ip = ida_dbg.get_ip_val()
    if ip is not None:
      return hex(ip)
  raise ToolError("Failed to step over")


@jsonrpc
@idaread
@unsafe
def dbg_delete_breakpoint(
    address: Annotated[str, "del a breakpoint at the specified address"],
):
  """Delete a breakpoint at the specified address."""
  ea = helper.parse_int(address)
  if idaapi.del_bpt(ea):
    return
  raise ToolError(f"Failed to delete breakpoint at address {ea:#x}")


@jsonrpc
@idaread
@unsafe
def dbg_enable_breakpoint(
    address: Annotated[
        str, "Enable or disable a breakpoint at the specified address"
    ],
    enable: Annotated[bool, "Enable or disable a breakpoint"],
):
  """Enable or disable a breakpoint at the specified address."""
  ea = helper.parse_int(address)
  if idaapi.enable_bpt(ea, enable):
    return
  raise ToolError(
      f"Failed to {'' if enable else 'disable '}breakpoint at address {ea:#x}"
  )
