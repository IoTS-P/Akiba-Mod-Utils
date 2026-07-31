#!/usr/bin/env python3
"""
angr taint propagation template.

Traces whether a value at a given program point is influenced by
user-controlled input (typically a function argument or a value read
from an external source like recv()/read()/fgets()).

Usage:
  1. Copy this file to your function's workspace directory:
       write_workspace_file {"path": "angr_check.py", "content": "..."}
  2. Fill in the parameters below (FUNC_ADDR, TARGET_ADDR, TAINT_SOURCE).
  3. Run:
       script_library action=run scriptName=run_angr_script \
         parameters={"scriptPath":"angr_check.py","timeout":180}

  4. Interpret the output:
     - "TAINTED"   → the target value is influenced by the tainted source.
       This means user input can reach the target operation.
     - "NOT TAINTED" → the target value is independent of the tainted source.
       The operation uses only constant/internal values.

NOTE — Architecture: this template is written for x86-64 (System V ABI).
If the target binary uses a different architecture (ARM, MIPS, x86-32,
AArch64, RISC-V, etc.), you MUST adapt the following:

  1. ARG_REGS list — replace with the argument registers for the target ABI:
       ARM:     ["r0", "r1", "r2", "r3"]
       AArch64: ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
       MIPS:    ["a0", "a1", "a2", "a3"]
       RISC-V:  ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
       x86-32:  arguments are passed on the stack (use "stack:0x4", "stack:0x8", etc.)
  2. Stack pointer register name ("rsp" → "sp" for ARM/AArch64/MIPS/RISC-V).
  3. The "64" in claripy.BVS() — replace with the target address width
     (32 for 32-bit architectures, 64 for 64-bit architectures).
  4. The "stdin" fallback register ("rdi" → the first argument register
     for the target ABI).

The angr framework itself is architecture-agnostic — it will detect the
binary's architecture automatically. Only the register/ABI specifics
in this template need adjustment.
"""

import os
import sys
import angr
import claripy

# ── Parameters (fill these in) ────────────────────────────────────────────────

# Function entry address.
FUNC_ADDR = "<FUNC_ADDR>"

# The instruction address where you want to check the value (e.g. the
# address of a memcpy call, a buffer store, a comparison).
TARGET_ADDR = "<TARGET_ADDR>"

# Taint source: how user input enters the function.
#
# Options:
#   "arg0", "arg1", ..., "arg5"  — function arguments (mapped to
#     rdi, rsi, rdx, rcx, r8, r9 on x86_64 System V ABI)
#   "memory:<addr>"             — a global/static buffer that holds
#     user input (e.g. a buffer filled by an earlier recv() call)
#   "stdin"                     — model the function as reading from stdin
#
# Default: "arg0" (first argument)
TAINT_SOURCE = "arg0"

# The register or memory location to check at TARGET_ADDR.
# Examples:
#   "rax"           — check if rax is tainted
#   "rsi"           — check if rsi is tainted (common for memcpy size)
#   "rdx"           — check if rdx is tainted (common for memcpy dest/src)
#   "stack:0x10"    — check a stack offset (relative to rsp)
#   "memory:<addr>" — check a global memory location
TARGET_LOCATION = "rsi"

# Timeout for symbolic execution (seconds).
EXPLORE_TIMEOUT = 120


# ── Architecture helpers ─────────────────────────────────────────────────────

# x86_64 System V ABI argument registers
ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]


def parse_addr(s):
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s, 16)


def main():
    binary = os.environ["AKIBA_BINARY_PATH"]
    proj = angr.Project(binary, auto_load_libs=False)

    func_addr = parse_addr(FUNC_ADDR)
    target_addr = parse_addr(TARGET_ADDR)

    print(f"[taint] Binary: {binary}")
    print(f"[taint] Function: {hex(func_addr)}")
    print(f"[taint] Target instruction: {hex(target_addr)}")
    print(f"[taint] Taint source: {TAINT_SOURCE}")
    print(f"[taint] Checking location: {TARGET_LOCATION}")
    print()

    # ── Create initial state at function entry ──
    state = proj.factory.blank_state(addr=func_addr)

    # Set up the taint source as a symbolic variable
    taint_var = claripy.BVS("taint_source", 64)

    if TAINT_SOURCE.startswith("arg"):
        arg_idx = int(TAINT_SOURCE[3])
        if arg_idx >= len(ARG_REGS):
            print(f"[taint] ERROR: argument index {arg_idx} out of range (max {len(ARG_REGS)-1})")
            sys.exit(1)
        reg_name = ARG_REGS[arg_idx]
        setattr(state.regs, reg_name, taint_var)
        print(f"[taint] Tainted {reg_name} (arg{arg_idx}) with symbolic variable 'taint_source'")

    elif TAINT_SOURCE.startswith("memory:"):
        mem_addr = parse_addr(TAINT_SOURCE.split(":", 1)[1])
        state.memory.store(mem_addr, taint_var)
        print(f"[taint] Tainted memory at {hex(mem_addr)} with symbolic variable 'taint_source'")

    elif TAINT_SOURCE == "stdin":
        # Model stdin as unconstrained symbolic data
        # The function may call read(0, buf, n) or similar
        print(f"[taint] Modeling stdin as unconstrained symbolic input")
        # For simplicity, taint the first argument register as if it
        # holds a pointer to user-controlled data
        setattr(state.regs, "rdi", taint_var)

    else:
        print(f"[taint] ERROR: unknown taint source '{TAINT_SOURCE}'")
        sys.exit(1)

    # ── Symbolic execution to target ──
    simgr = proj.factory.simulation_manager(state)

    print(f"[taint] Exploring to {hex(target_addr)} (timeout={EXPLORE_TIMEOUT}s) ...")
    simgr.explore(find=[target_addr])

    if not simgr.found:
        print()
        print("=" * 60)
        print("TARGET NOT REACHED")
        print("=" * 60)
        print(f"Could not reach {hex(target_addr)} from {hex(func_addr)}.")
        print("Taint analysis is inconclusive — the path may be infeasible")
        print("or the exploration timed out. Try:")
        print("  - Adding AVOID_ADDRS to prune irrelevant paths")
        print("  - Increasing EXPLORE_TIMEOUT")
        print("  - Checking if TARGET_ADDR is behind an indirect call")
        sys.exit(1)

    # ── Check taint at the target state ──
    found_state = simgr.found[0]

    print()
    print("=" * 60)

    if TARGET_LOCATION.startswith("stack:"):
        # Stack-relative check
        offset_str = TARGET_LOCATION.split(":", 1)[1]
        offset = parse_addr(offset_str)
        sp = found_state.regs.rsp
        if sp.symbolic:
            print("CANNOT CHECK — stack pointer is symbolic")
            sys.exit(1)
        sp_val = sp.concrete_value
        mem_val = found_state.memory.load(sp_val + offset, 8)
        is_tainted = mem_val.symbolic and found_state.solver.eval(
            mem_val == taint_var, extra_constraints=[]
        )
        print(f"Stack value at [rsp+{hex(offset)}]: {'TAINTED' if is_tainted else 'NOT TAINTED'}")

    elif TARGET_LOCATION.startswith("memory:"):
        mem_addr = parse_addr(TARGET_LOCATION.split(":", 1)[1])
        mem_val = found_state.memory.load(mem_addr, 8)
        is_tainted = mem_val.symbolic and found_state.solver.eval(
            mem_val == taint_var, extra_constraints=[]
        )
        print(f"Memory at {hex(mem_addr)}: {'TAINTED' if is_tainted else 'NOT TAINTED'}")

    else:
        # Register check
        reg_val = getattr(found_state.regs, TARGET_LOCATION, None)
        if reg_val is None:
            print(f"[taint] ERROR: unknown register '{TARGET_LOCATION}'")
            sys.exit(1)

        # Check if the register value depends on our taint variable
        if reg_val.symbolic:
            # The register holds a symbolic expression — check if our
            # taint variable appears in it
            vars_in_expr = reg_val.variables
            if "taint_source" in str(vars_in_expr):
                print("TAINTED")
                print("=" * 60)
                print(f"Register '{TARGET_LOCATION}' at {hex(target_addr)} is TAINTED.")
                print(f"The value depends on the tainted source ({TAINT_SOURCE}).")
                print()
                print(f"Expression: {reg_val}")
                print()
                print("This means user-controlled input can influence the value")
                print("used at this program point. If this is a size parameter,")
                print("array index, or pointer, it may be exploitable.")
            else:
                print("NOT TAINTED")
                print("=" * 60)
                print(f"Register '{TARGET_LOCATION}' at {hex(target_addr)} is NOT tainted.")
                print(f"The value is symbolic but does not depend on the tainted source.")
                print(f"Expression: {reg_val}")
        else:
            concrete = reg_val.concrete_value
            print("NOT TAINTED")
            print("=" * 60)
            print(f"Register '{TARGET_LOCATION}' at {hex(target_addr)} is NOT tainted.")
            print(f"The value is concrete: {hex(concrete)}")
            print("The operation uses a constant value, not user input.")

    print("=" * 60)


if __name__ == "__main__":
    main()
