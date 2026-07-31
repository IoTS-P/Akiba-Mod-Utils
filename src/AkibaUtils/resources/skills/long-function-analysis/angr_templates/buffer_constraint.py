#!/usr/bin/env python3
"""
angr buffer constraint template.

Checks whether a size variable at a given program point can exceed
a buffer's allocated length, proving (or disproving) that a buffer
overflow / out-of-bounds access is reachable.

Usage:
  1. Copy this file to your function's workspace directory:
       write_workspace_file {"path": "angr_check.py", "content": "..."}
  2. Fill in the parameters below.
  3. Run:
       script_library action=run scriptName=run_angr_script \
         parameters={"scriptPath":"angr_check.py","timeout":180}

  4. Interpret the output:
     - "OVERFLOW REACHABLE" → the size variable CAN exceed the buffer length.
       An overflow is possible. The output shows the concrete size value
       that triggers it.
     - "OVERFLOW NOT REACHABLE" → the size variable is always bounded by
       the buffer length under the given constraints. Safe (for this path).

NOTE — Architecture: this template is written for x86-64 (System V ABI).
If the target binary uses a different architecture (ARM, MIPS, x86-32,
AArch64, RISC-V, etc.), you MUST adapt the following:

  1. Register names in SIZE_LOCATION and BUFFER_LEN_LOCATION — replace
     with the registers used by the target ABI for the corresponding
     operation (e.g. on ARM, memcpy's size is typically in "r2"; on
     AArch64, in "x2"; on MIPS, in "a2").
  2. Stack pointer register name ("rsp" → "sp" for ARM/AArch64/MIPS/RISC-V).
  3. The "64" in claripy.BVS() and the 8-byte memory load size in
     resolve_location() — replace with the target address width and
     pointer size (32/4 for 32-bit architectures, 64/8 for 64-bit).
  4. SIZE_SOURCE_CONSTRAINTS register names — same ABI mapping as above.

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

# Address of the vulnerable operation (e.g. memcpy, strcpy, buffer store).
# The analysis checks the state at THIS instruction.
VULN_OP_ADDR = "<VULN_OP_ADDR>"

# The register or memory location holding the SIZE value (how many bytes
# will be copied / written / read).
# Examples:
#   "rsi"           — common for memcpy's n parameter
#   "rdx"           — common for memcpy's src or dest
#   "stack:0x10"    — a stack variable holding the size
SIZE_LOCATION = "rsi"

# The buffer's allocated length (in bytes). This is the maximum safe
# value for the size variable. You need to determine this from the
# allocation site (e.g. malloc(N), char buf[N], etc.).
#
# If the buffer length is itself symbolic (e.g. from malloc(n) where n
# is a function argument), set BUFFER_LEN to a symbolic expression or
# leave it as None and provide the register/location holding the length.
BUFFER_LEN = None  # e.g. 256, 0x100

# Alternative: the register/location holding the buffer length.
# If BUFFER_LEN is set, this is ignored.
# Examples: "rdi", "stack:0x20", "memory:0x601040"
BUFFER_LEN_LOCATION = None  # e.g. "rdi"

# Optional: constrain the size variable's source (e.g. it comes from
# an argument or a global variable). This helps angr narrow the search.
# Leave empty to explore without constraints.
SIZE_SOURCE_CONSTRAINTS = {}

# Timeout for symbolic execution (seconds).
EXPLORE_TIMEOUT = 120


# ── Main logic ────────────────────────────────────────────────────────────────

def parse_addr(s):
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s, 16)


def resolve_location(state, location):
    """Resolve a register/stack/memory location string to a claripy AST."""
    if location.startswith("stack:"):
        offset = parse_addr(location.split(":", 1)[1])
        sp = state.regs.rsp
        if sp.symbolic:
            return None, "stack pointer is symbolic"
        sp_val = sp.concrete_value
        return state.memory.load(sp_val + offset, 8), None
    elif location.startswith("memory:"):
        addr = parse_addr(location.split(":", 1)[1])
        return state.memory.load(addr, 8), None
    else:
        val = getattr(state.regs, location, None)
        if val is None:
            return None, f"unknown register '{location}'"
        return val, None


def main():
    binary = os.environ["AKIBA_BINARY_PATH"]
    proj = angr.Project(binary, auto_load_libs=False)

    func_addr = parse_addr(FUNC_ADDR)
    vuln_addr = parse_addr(VULN_OP_ADDR)

    print(f"[buffer] Binary: {binary}")
    print(f"[buffer] Function: {hex(func_addr)}")
    print(f"[buffer] Vulnerable operation: {hex(vuln_addr)}")
    print(f"[buffer] Size location: {SIZE_LOCATION}")
    if BUFFER_LEN is not None:
        print(f"[buffer] Buffer length: {BUFFER_LEN} bytes (constant)")
    elif BUFFER_LEN_LOCATION:
        print(f"[buffer] Buffer length location: {BUFFER_LEN_LOCATION}")
    print()

    # ── Create initial state ──
    state = proj.factory.blank_state(addr=func_addr)

    # Apply size source constraints
    for reg_name, value in SIZE_SOURCE_CONSTRAINTS.items():
        if isinstance(value, list):
            sym_var = claripy.BVS(f"src_{reg_name}", 64)
            state.add_constraints(sym_var >= value[0])
            state.add_constraints(sym_var <= value[1])
            setattr(state.regs, reg_name, sym_var)
            print(f"[buffer] Constrained {reg_name} to [{hex(value[0])}, {hex(value[1])}]")
        else:
            setattr(state.regs, reg_name, value)
            print(f"[buffer] Constrained {reg_name} = {hex(value)}")

    # ── Symbolic execution to the vulnerable operation ──
    simgr = proj.factory.simulation_manager(state)

    print(f"[buffer] Exploring to {hex(vuln_addr)} (timeout={EXPLORE_TIMEOUT}s) ...")
    simgr.explore(find=[vuln_addr])

    if not simgr.found:
        print()
        print("=" * 60)
        print("VULNERABLE OPERATION NOT REACHED")
        print("=" * 60)
        print(f"Could not reach {hex(vuln_addr)} from {hex(func_addr)}.")
        print("Buffer analysis is inconclusive — the path may be infeasible")
        print("or the exploration timed out.")
        sys.exit(1)

    # ── Check the size value at the vulnerable operation ──
    found_state = simgr.found[0]

    size_val, err = resolve_location(found_state, SIZE_LOCATION)
    if err:
        print(f"[buffer] ERROR: {err}")
        sys.exit(1)

    print()
    print("=" * 60)
    print("BUFFER CONSTRAINT ANALYSIS")
    print("=" * 60)
    print()

    # ── Determine buffer length ──
    if BUFFER_LEN is not None:
        buf_len = BUFFER_LEN
        buf_len_desc = f"constant {buf_len}"
    elif BUFFER_LEN_LOCATION:
        buf_len_val, err = resolve_location(found_state, BUFFER_LEN_LOCATION)
        if err:
            print(f"[buffer] ERROR resolving buffer length: {err}")
            sys.exit(1)
        if buf_len_val.symbolic:
            # Buffer length is symbolic — use solver to get its max
            buf_len = found_state.solver.max(buf_len_val)
            buf_len_desc = f"symbolic (max={buf_len})"
        else:
            buf_len = buf_len_val.concrete_value
            buf_len_desc = f"concrete {buf_len}"
    else:
        print("[buffer] ERROR: must set BUFFER_LEN or BUFFER_LEN_LOCATION")
        sys.exit(1)

    print(f"[buffer] Size value: {size_val}")
    print(f"[buffer] Buffer length: {buf_len_desc}")
    print()

    # ── Check if size > buffer_len is satisfiable ──
    if size_val.symbolic:
        # Size is symbolic — check if it can exceed the buffer length
        overflow_constraint = size_val > buf_len

        if found_state.solver.satisfiable(extra_constraints=[overflow_constraint]):
            # Overflow is reachable — get a concrete example
            overflow_size = found_state.solver.eval(size_val, extra_constraints=[overflow_constraint])
            print("OVERFLOW REACHABLE")
            print("=" * 60)
            print(f"The size variable CAN exceed the buffer length ({buf_len}).")
            print(f"Example overflow size: {overflow_size} (0x{overflow_size:x})")
            print(f"Overflow amount: {overflow_size - buf_len} bytes")
            print()
            print("This means an attacker-controlled value can cause a buffer")
            print("overflow / out-of-bounds access at this program point.")
            print("Record this as a vulnerability with the concrete size value")
            print("as evidence.")

            # Also show the minimum size needed to trigger overflow
            min_overflow = found_state.solver.min(size_val, extra_constraints=[overflow_constraint])
            print(f"Minimum size to trigger overflow: {min_overflow} (0x{min_overflow:x})")

            # Show what the safe bound would be
            max_safe = found_state.solver.max(size_val, extra_constraints=[size_val <= buf_len])
            print(f"Maximum safe size: {max_safe} (0x{max_safe:x})")

        else:
            print("OVERFLOW NOT REACHABLE")
            print("=" * 60)
            print(f"The size variable CANNOT exceed the buffer length ({buf_len})")
            print("under the current constraints.")
            print()
            print("This does NOT necessarily mean the code is safe:")
            print("  - The constraints may be too restrictive")
            print("  - The size may be controllable from a different source")
            print("  - The buffer length may be incorrect")
            print("Verify the buffer length is correct before concluding safety.")

    else:
        # Size is concrete
        concrete_size = size_val.concrete_value
        if concrete_size > buf_len:
            print("OVERFLOW REACHABLE (concrete)")
            print("=" * 60)
            print(f"Size is concrete: {concrete_size} > buffer length {buf_len}")
            print(f"Overflow amount: {concrete_size - buf_len} bytes")
            print()
            print("This is a DEFINITE buffer overflow — no symbolic analysis needed.")
        else:
            print("OVERFLOW NOT REACHABLE (concrete)")
            print("=" * 60)
            print(f"Size is concrete: {concrete_size} <= buffer length {buf_len}")
            print("No overflow at this program point (for this concrete value).")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
