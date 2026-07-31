#!/usr/bin/env python3
"""
angr reachability check template.

Checks whether a target basic block / instruction address is reachable
from the function entry point under realistic path constraints.

Usage:
  1. Copy this file to your function's workspace directory:
       write_workspace_file {"path": "angr_check.py", "content": "..."}
  2. Fill in the parameters below (FUNC_ADDR, TARGET_ADDR, AVOID_ADDRS).
  3. Run:
       script_library action=run scriptName=run_angr_script \
         parameters={"scriptPath":"angr_check.py","timeout":180}

  4. Interpret the output:
     - "REACHABLE"  → the target is reachable; inspect the printed register
       values to understand the input conditions that lead there.
     - "UNREACHABLE" → the target cannot be reached from the entry under
       the given constraints. Verify that your constraints are correct
       before concluding the path is impossible.

NOTE — Architecture: this template is written for x86-64 (System V ABI).
If the target binary uses a different architecture (ARM, MIPS, x86-32,
AArch64, RISC-V, etc.), you MUST adapt the following:

  1. Register names in CONSTRAINTS and the output section (e.g. "rdi" →
     the appropriate argument register for the target ABI, such as "r0"
     for ARM, "a0" for MIPS/AArch64, "a0" for RISC-V).
  2. Stack pointer register name ("rsp" → "sp" for ARM/AArch64, "sp" for
     MIPS, "sp" for RISC-V, etc.).
  3. The number of argument registers (x86-64 SysV has 6; ARM has r0-r3;
     MIPS has a0-a3; AArch64 has x0-x7; RISC-V has a0-a7).
  4. Address sizes: replace "64" in claripy.BVS() calls with the target
     architecture's address width (32 for 32-bit architectures, 64 for
     64-bit architectures).
  5. The register list printed in the output section — adjust to the
     registers relevant to the target architecture.

The angr framework itself is architecture-agnostic — it will detect the
binary's architecture automatically. Only the register/ABI specifics
in this template need adjustment.
"""

import os
import sys
import angr

# ── Parameters (fill these in) ────────────────────────────────────────────────

# Function entry address (hex string, e.g. "0x401000" or "401000").
# Use the address from Ghidra's function list, NOT the pseudo-C line number.
FUNC_ADDR = "<FUNC_ADDR>"

# Target address to check reachability for (the basic block / instruction
# you want to confirm is reachable). Same format as FUNC_ADDR.
TARGET_ADDR = "<TARGET_ADDR>"

# Optional: addresses to AVOID during exploration (e.g. error-handling
# blocks that you know are irrelevant, or loops that cause path explosion).
# Leave empty to explore all paths.
AVOID_ADDRS = [
    # "<AVOID_ADDR_1>",
    # "<AVOID_ADDR_2>",
]

# Optional: constrain an input register to a specific value (or range).
# This is useful when you know the function is called with specific
# argument values from a call site.
# Example: CONSTRAINTS = {"rdi": 0x100, "rsi": [0x200, 0x300]}
# Leave empty to explore without input constraints.
CONSTRAINTS = {}

# Timeout for the exploration phase (seconds).  If the exploration
# doesn't finish within this time, partial results are still reported.
EXPLORE_TIMEOUT = 120


# ── Main logic ────────────────────────────────────────────────────────────────

def parse_addr(s):
    """Parse a hex address string like '0x401000' or '401000' to int."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s, 16)


def main():
    binary = os.environ["AKIBA_BINARY_PATH"]
    proj = angr.Project(binary, auto_load_libs=False)

    func_addr = parse_addr(FUNC_ADDR)
    target_addr = parse_addr(TARGET_ADDR)
    avoid_addrs = [parse_addr(a) for a in AVOID_ADDRS]

    print(f"[reachability] Binary: {binary}")
    print(f"[reachability] Function: {hex(func_addr)}")
    print(f"[reachability] Target:   {hex(target_addr)}")
    print(f"[reachability] Avoiding: {[hex(a) for a in avoid_addrs]}")
    print()

    # ── Build CFG (needed for function resolution) ──
    cfg = proj.analyses.CFGFast(normalize=True)

    # Resolve the function object
    func = cfg.functions.get(func_addr)
    if func is None:
        # Try by name
        func = cfg.functions.get(FUNC_ADDR)
    if func is None:
        print(f"[reachability] ERROR: function at {hex(func_addr)} not found in CFG.")
        print("[reachability] Available functions near target:")
        for f in cfg.functions.values():
            if abs(f.addr - func_addr) < 0x1000:
                print(f"  {hex(f.addr)}: {f.name}")
        sys.exit(1)

    print(f"[reachability] Resolved function: {func.name} @ {hex(func.addr)}")
    print(f"[reachability] Function size: {func.size} bytes, {len(list(func.blocks))} blocks")

    # ── Create initial state ──
    state = proj.factory.blank_state(addr=func.addr)

    # Apply input constraints
    for reg_name, value in CONSTRAINTS.items():
        if isinstance(value, list):
            # Range constraint: symbolic value bounded to [lo, hi]
            sym_var = angr.claripy.BVS(f"input_{reg_name}", 64)
            state.add_constraints(sym_var >= value[0])
            state.add_constraints(sym_var <= value[1])
            setattr(state.regs, reg_name, sym_var)
            print(f"[reachability] Constrained {reg_name} to range [{hex(value[0])}, {hex(value[1])}]")
        else:
            # Fixed value
            setattr(state.regs, reg_name, value)
            print(f"[reachability] Constrained {reg_name} = {hex(value)}")

    # ── Symbolic execution ──
    simgr = proj.factory.simulation_manager(state)

    find_addrs = [target_addr]
    avoid_list = avoid_addrs if avoid_addrs else None

    print(f"[reachability] Exploring (timeout={EXPLORE_TIMEOUT}s) ...")
    simgr.explore(find=find_addrs, avoid=avoid_list)

    # ── Report results ──
    print()
    if simgr.found:
        found_state = simgr.found[0]
        print("=" * 60)
        print("REACHABLE")
        print("=" * 60)
        print(f"Target {hex(target_addr)} is reachable from {hex(func_addr)}.")
        print()
        print("Key register values at the found state:")
        for reg in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]:
            try:
                val = getattr(found_state.regs, reg)
                if not val.symbolic:
                    print(f"  {reg} = {hex(val.concrete_value)}")
                else:
                    # Try to get a satisfiable concrete value
                    concrete = found_state.solver.eval(val, cast_to=int)
                    print(f"  {reg} = {hex(concrete)} (symbolic)")
            except Exception:
                pass
        print()
        print("Stack pointer region (top 10 qwords):")
        try:
            sp = found_state.regs.rsp
            if not sp.symbolic:
                sp_val = sp.concrete_value
                for i in range(10):
                    try:
                        mem = found_state.memory.load(sp_val + i * 8, 8)
                        if not mem.symbolic:
                            print(f"  [rsp+{i*8:3d}] = {hex(mem.concrete_value)}")
                        else:
                            print(f"  [rsp+{i*8:3d}] = <symbolic>")
                    except Exception:
                        break
        except Exception:
            pass
    else:
        print("=" * 60)
        print("UNREACHABLE")
        print("=" * 60)
        print(f"Target {hex(target_addr)} was NOT reached from {hex(func_addr)}")
        print("under the given constraints.")
        print()
        print("Consider:")
        print("  - Are your AVOID_ADDRS excluding too many paths?")
        print("  - Are your CONSTRAINTS too restrictive?")
        print("  - Is the target behind an indirect call/jump that needs resolution?")

    print()
    print(f"[reachability] Active states remaining: {len(simgr.active)}")
    print(f"[reachability] Deadended states: {len(simgr.deadended)}")
    print(f"[reachability] Errored states: {len(simgr.errored)}")


if __name__ == "__main__":
    main()
