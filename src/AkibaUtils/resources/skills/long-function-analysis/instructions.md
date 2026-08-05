# Long Function Analysis

## When to use

Use this skill when analyzing a function whose disassembly exceeds ~120 instructions. For such functions, `disassemble_function` cannot return all instructions in a single tool call (the output is truncated by context limits), and using `addressAfter` to page through the remaining instructions is inefficient — earlier pages get compacted before the LLM finishes reading later pages, so the LLM never sees the full function at once.

## Core approach: Pseudo-C first, assembly verification

For long functions, **start with the decompiled pseudo-C code** and use assembly only for targeted verification of suspicious lines. This is the inverse of the default (assembly-first) workflow used for short functions.

### Step 1: Export the analysis package

```
script_library action=run scriptName=export_function_analysis parameters={"target":"<function_name_or_addr>"}
```

This creates a directory under `functions/<addr>_<name>/` in the workspace containing:

| File | Description |
|------|-------------|
| `disasm.txt` | Full disassembly — **all** instructions, never truncated |
| `decomp.c` | Full decompiled pseudo-C code |
| `mapping.json` | Statement-level mapping: each C statement → its assembly addresses |
| `meta.json` | Function metadata (size, params, calling convention, etc.) |

### Step 2: Read the pseudo-C code

```
read_workspace_file {"path": "functions/<addr>_<name>/decomp.c"}
```

The pseudo-C code is typically 5-10x more compact than assembly. A 1000-instruction function may produce only 50-100 lines of C. Read it in full — this gives you the overall function logic.

**Caveat**: Ghidra's decompiler may produce inaccurate results:
- Wrong types (e.g. `int` instead of `char*`)
- Wrong variable names (`param_1`, `local_20`, etc.)
- Failed switch-table reconstruction (shows as `switch(...)` with `default:` only)
- Missing struct fields (accessed as `*(int*)(param_1 + 0x10)` instead of `param_1->field`)

### Step 3: Read the mapping

```
read_workspace_file {"path": "functions/<addr>_<name>/mapping.json"}
```

The mapping contains a `statements` array. Each entry has:
- `index`: statement index (0-based)
- `cText`: the C statement text
- `asmRange`: address range covered (`minAddr-maxAddr`)
- `asmAddrs`: list of individual instruction addresses (may be non-contiguous)
- `asmIndices`: 1-based instruction indices in disasm.txt
- `rootAddr`: the primary instruction address (root PcodeOp)

### Step 4: Verify suspicious lines against assembly

When you find a suspicious pattern in the pseudo-C code (e.g. a `memcpy` with a tainted size, an unchecked buffer access, a switch with missing cases):

1. Note the `cText` of the suspicious statement
2. Look up its `asmAddrs` / `asmIndices` in `mapping.json`
3. Read the corresponding lines from `disasm.txt`:

```
read_workspace_file {"path": "functions/<addr>_<name>/disasm.txt", "maxChars": 200000}
```

Since `disasm.txt` contains the **full** disassembly (never truncated by the script), you can read it in chunks or use `grep_workspace` to find specific addresses:

```
grep_workspace {"pattern": "0012589c", "path": "functions/<addr>_<name>/disasm.txt"}
```

### Step 5: Fix variable types and names (persist to Ghidra)

If the pseudo-C code has inaccurate local variable types or generic names (`local_8`, `iVar1`), fix them via `manage_func_vars` to get a better decompiler output:

```
# Single variable:
script_library action=run scriptName=manage_func_vars parameters={"address":"<addr>","name":"local_8","newName":"buf","newType":"char*"}

# Batch mode (recommended — one decompilation pass for multiple changes):
script_library action=run scriptName=manage_func_vars parameters={"address":"<addr>","operations":"[{\"name\":\"local_8\",\"newName\":\"buf\",\"newType\":\"char*\"},{\"name\":\"iVar1\",\"newName\":\"len\",\"newType\":\"size_t\"}]"}
```

After fixing variables, **re-export the analysis package** to get updated pseudo-C code with the corrected types and names:

```
script_library action=run scriptName=export_function_analysis parameters={"target":"<addr>"}
```

This overwrites `decomp.c` and `mapping.json` in the workspace with the improved output. The mapping is regenerated from the new decompiler output, so the C↔assembly correspondence remains accurate.

**Note**: `manage_func_vars` modifies LOCAL variables only (not parameters). Use `manage_func_signature` for parameter/return-type changes.

### Step 6: Reconstruct accurate C code (optional but recommended)

Based on your understanding from the pseudo-C code and assembly verification, write a corrected C version of the function. Save it to the workspace:

```
write_workspace_file {"path": "functions/<addr>_<name>/reconstructed.c", "content": "// Reconstructed C code\n..."}
```

In the reconstructed code:
- Fix variable types and names based on usage analysis
- Reconstruct switch tables that Ghidra failed to decode
- Add comments explaining bug patterns found
- Mark uncertain sections with `// TODO: verify`

This reconstructed code serves as:
1. Your understanding of the function (for vulnerability analysis)
2. A reference for other agents in subsequent rounds
3. Evidence that you thoroughly analyzed the function

### Step 7: Record findings

Use `vuln_memory` to record any vulnerabilities found, and `set_get_comment` to update the AKIBA: PLATE comment with your analysis status. Reference the workspace files in the comment so other agents can find your detailed analysis:

```
AKIBA: role=<purpose>; status=<clean|candidate|confirmed>; analysis=exported; files=functions/<addr>_<name>/
```

## Data-flow and control-flow verification

**Data-flow and control-flow conclusions MUST be verified against the actual assembly before recording them.** Ghidra's decompiler provides a static approximation that can be inaccurate — especially for complex control flow (switch tables, indirect jumps), pointer aliasing, and value propagation. When your analysis depends on such a conclusion (e.g. "this buffer size is attacker-controlled", "this branch is reachable", "this pointer always points to struct X"):

1. Locate the relevant C statement in `mapping.json` and get its `asmAddrs`.
2. Read those instructions in `disasm.txt` and trace the value/branch manually through the surrounding basic blocks (use `grep_workspace` on `disasm.txt` to follow register definitions and xrefs).
3. Only record the conclusion once the assembly-level trace supports it; otherwise mark it as unverified in your findings.

## Important notes

- **To persist analysis improvements, use `manage_func_vars` then re-export** — this is the correct way to improve Ghidra's decompiler output. Do NOT use `manage_func_signature` for local variables (it handles parameters/return types only).
- **After fixing variables, always re-export** — the mapping in `mapping.json` is tied to the decompiler output at export time. If you modify variables (which changes the decompiler output), the old mapping is stale.
- **The mapping is at statement level, not line level** — a single C statement (e.g. `if (a > b) goto X`) may map to multiple non-contiguous assembly addresses. Use `asmAddrs` for the complete list.
- **Always verify before concluding** — if the pseudo-C code shows a potential vulnerability, verify it against the actual assembly before recording it. The decompiler may have misrepresented the operation.
- **For switch tables** — if Ghidra failed to reconstruct a switch table, the pseudo-C code will show a series of `if-else` chains or a `goto` to a computed address. Use the assembly to identify the jump table and enumerate all cases.
