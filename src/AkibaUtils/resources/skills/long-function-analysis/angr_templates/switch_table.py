#!/usr/bin/env python3
"""
angr switch table reconstruction template.

Reconstructs a switch jump table that Ghidra failed to decode.
Enumerates all cases, their target addresses, and the constraint
on the switch variable for each case.

Usage:
  1. Copy this file to your function's workspace directory:
       write_workspace_file {"path": "angr_check.py", "content": "..."}
  2. Fill in the parameters below (FUNC_ADDR, SWITCH_ADDR).
  3. Run:
       script_library action=run scriptName=run_angr_script \
         parameters={"scriptPath":"angr_check.py","timeout":180}

  4. Interpret the output:
     - Lists each case: its value range, target address, and the
       constraint on the switch variable that leads to that target.
     - "default" case is the fall-through when no case matches.

NOTE — Architecture: this template is written for x86-64 (System V ABI).
If the target binary uses a different architecture (ARM, MIPS, x86-32,
AArch64, RISC-V, etc.), you MUST adapt the following:

  1. The regex pattern used to auto-detect the switch register from the
     capstone instruction string — it matches x86-64 register names
     (rax-r15). Replace with the target architecture's register pattern:
       ARM:     r'\\b(r[0-9]|r1[0-5]|sp|lr|pc)\\b'
       AArch64: r'\\b(x[0-9]|x1[0-9]|x2[0-8]|sp|lr)\\b'
       MIPS:    r'\\b(a[0-3]|t[0-9]|s[0-8]|v[01]|sp|ra)\\b'
       RISC-V:  r'\\b(a[0-7]|t[0-6]|s[0-9]|s1[01]|sp|ra)\\b'
  2. Indirect jump instruction format — x86 uses `jmp [reg*scale + base]`,
     ARM uses `bx reg` or `ldr pc, [reg, offset]`, AArch64 uses `br reg`,
     MIPS uses `jr reg`, RISC-V uses `jr reg` or `jalr zero, 0(reg)`.
     The capstone decoding will differ — check the printed instruction
     and adjust SWITCH_VAR_REG accordingly.
  3. Stack pointer register name ("rsp" → "sp" for ARM/AArch64/MIPS/RISC-V).
  4. The "64" in claripy.BVS() — replace with the target address width.

The angr framework itself is architecture-agnostic — it will detect the
binary's architecture automatically. Only the register/ABI specifics
in this template need adjustment.
"""

import os
import sys
import angr
import claripy

# ── Parameters (fill these in) ────────────────────────────────────────────────

# Function entry address containing the switch statement.
FUNC_ADDR = "<FUNC_ADDR>"

# Address of the indirect jump instruction (e.g. `jmp [rax*8 + table]`).
# This is the instruction Ghidra couldn't resolve — look for `jmp` or
# `call` with a computed target in the disassembly near the switch.
SWITCH_ADDR = "<SWITCH_ADDR>"

# Optional: the register that holds the switch variable (usually rax,
# or a value derived from a function argument). Leave as None to
# let angr figure it out.
SWITCH_VAR_REG = None  # e.g. "rax", "rcx", "rdi"

# Maximum number of cases to enumerate (safety limit).
MAX_CASES = 256


# ── Main logic ────────────────────────────────────────────────────────────────

def parse_addr(s):
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s, 16)


def main():
    binary = os.environ["AKIBA_BINARY_PATH"]
    proj = angr.Project(binary, auto_load_libs=False)

    func_addr = parse_addr(FUNC_ADDR)
    switch_addr = parse_addr(SWITCH_ADDR)

    print(f"[switch] Binary: {binary}")
    print(f"[switch] Function: {hex(func_addr)}")
    print(f"[switch] Indirect jump: {hex(switch_addr)}")
    print()

    # ── Build CFG ──
    cfg = proj.analyses.CFGFast(normalize=True)

    func = cfg.functions.get(func_addr)
    if func is None:
        func = cfg.functions.get(FUNC_ADDR)
    if func is None:
        print(f"[switch] ERROR: function at {hex(func_addr)} not found.")
        sys.exit(1)

    print(f"[switch] Resolved function: {func.name} @ {hex(func.addr)}")

    # ── Symbolic execution to the switch point ──
    state = proj.factory.blank_state(addr=func.addr)
    simgr = proj.factory.simulation_manager(state)

    print(f"[switch] Exploring to switch point at {hex(switch_addr)} ...")
    simgr.explore(find=[switch_addr])

    if not simgr.found:
        print(f"[switch] ERROR: could not reach switch point {hex(switch_addr)}.")
        print("The switch may be behind an indirect call or an unresolved branch.")
        sys.exit(1)

    switch_state = simgr.found[0]

    # ── Identify the switch variable ──
    # The instruction at switch_addr is typically `jmp [reg*scale + base]`
    # or `jmp [reg]`. We need to find which register holds the computed target.
    print(f"[switch] Analyzing switch variable ...")

    # Get the instruction at the switch address
    block = proj.factory.block(switch_addr)
    insn = block.capstone.insns[-1] if block.capstone.insns else None
    if insn is None:
        print(f"[switch] ERROR: could not decode instruction at {hex(switch_addr)}")
        sys.exit(1)

    print(f"[switch] Instruction: {insn.mnemonic} {insn.op_str}")

    # Try to identify the switch variable register
    if SWITCH_VAR_REG:
        switch_reg = SWITCH_VAR_REG
    else:
        # Auto-detect: look for the register used in the indirect jump
        # Common patterns:
        #   jmp qword ptr [rax*8 + 0x12345]
        #   jmp qword ptr [rcx + rdx*8]
        #   jmp rax
        op_str = insn.op_str
        if "[" in op_str and "]" in op_str:
            # Extract register from memory operand
            import re
            regs = re.findall(r'\b(r[a-c][x|]|r[sd]i|rbp|rsp|r[89]|r1[0-5])\b', op_str)
            if regs:
                switch_reg = regs[0]
            else:
                print(f"[switch] WARNING: could not auto-detect switch register from '{op_str}'")
                print("[switch] Please set SWITCH_VAR_REG manually.")
                sys.exit(1)
        else:
            # Direct register jump: jmp rax
            switch_reg = op_str.strip()

    print(f"[switch] Switch variable register: {switch_reg}")

    switch_val = getattr(switch_state.regs, switch_reg, None)
    if switch_val is None:
        print(f"[switch] ERROR: register '{switch_reg}' not found in state")
        sys.exit(1)

    # ── Enumerate possible targets ──
    print()
    print("=" * 60)
    print("SWITCH TABLE RECONSTRUCTION")
    print("=" * 60)
    print()

    if switch_val.symbolic:
        # The switch variable is symbolic — enumerate possible values
        # and resolve each to a target address.
        print(f"[switch] Switch variable is symbolic: {switch_val}")
        print()

        # Get the range of possible values
        try:
            min_val = switch_state.solver.min(switch_val)
            max_val = switch_state.solver.max(switch_val)
            print(f"[switch] Possible range: [{min_val}, {max_val}] (0x{min_val:x} - 0x{max_val:x})")
        except Exception:
            min_val = 0
            max_val = MAX_CASES - 1
            print(f"[switch] Could not determine range, assuming 0-{MAX_CASES-1}")

        if max_val - min_val > MAX_CASES:
            print(f"[switch] WARNING: range too large ({max_val - min_val + 1} values), capping at {MAX_CASES}")
            max_val = min_val + MAX_CASES - 1

        print()
        print(f"{'Case':>6} {'Value':>10} {'Target':>12} {'Constraint'}")
        print("-" * 70)

        cases_found = 0
        for case_val in range(min_val, min(max_val + 1, min_val + MAX_CASES)):
            # Create a copy of the state constrained to this case value
            case_state = switch_state.copy()
            case_state.add_constraints(switch_val == case_val)

            if case_state.satisfiable():
                # Step the state to execute the indirect jump
                case_simgr = proj.factory.simulation_manager(case_state)
                case_simgr.step()

                if case_simgr.active:
                    target = case_simgr.active[0].addr
                    constraint = f"{switch_reg} == {case_val} (0x{case_val:x})"
                    print(f"{'case':>6} {case_val:>10} {hex(target):>12} {constraint}")
                    cases_found += 1
                else:
                    print(f"{'case':>6} {case_val:>10} {'<no successor>':>12} (dead end)")
            else:
                # This case value is not reachable
                pass

        print()
        print(f"[switch] Found {cases_found} reachable case(s).")

        # Check for default case
        if cases_found < (max_val - min_val + 1):
            print()
            print("Note: some case values in the range were not reachable.")
            print("This may indicate:")
            print("  - A default/fall-through case (values outside the switch range)")
            print("  - Invalid case values that are filtered by prior constraints")
            print("  - The range is larger than the actual switch table")

    else:
        # The switch variable is concrete — just resolve the target
        concrete_val = switch_val.concrete_value
        print(f"[switch] Switch variable is concrete: {hex(concrete_val)}")

        switch_simgr = proj.factory.simulation_manager(switch_state)
        switch_simgr.step()

        if switch_simgr.active:
            target = switch_simgr.active[0].addr
            print(f"[switch] Single target: {hex(target)}")
        else:
            print("[switch] No successor state after the jump (dead end).")

    print()
    print("=" * 60)
    print("Cross-reference the targets above with Ghidra's disassembly.")
    print("If Ghidra shows 'if-else' chains instead of a switch, the targets")
    print("above are the actual case handlers. Map them back to the C code:")
    print("  - Each target address should correspond to a 'case N:' label")
    print("  - The constraint shows which value of the switch variable leads there")
    print("  - If a target is shared by multiple cases, they fall through to the")
    print("    same handler (common for grouped cases like 'case 1: case 2: ...')")


if __name__ == "__main__":
    main()
