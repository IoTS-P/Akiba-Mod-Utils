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

## Data-flow and control-flow verification with angr

**Data-flow and control-flow analysis MUST be confirmed using angr scripts.** Ghidra's decompiler and disassembler provide a static view that can be inaccurate — especially for complex control flow (switch tables, indirect jumps), pointer aliasing, and taint propagation. When your analysis depends on data-flow or control-flow conclusions (e.g. "this buffer size is attacker-controlled", "this branch is reachable", "this pointer always points to struct X"), write an angr script to confirm the result before recording it.

### Quick start: use a template

This skill includes pre-written angr templates for common analysis tasks. Instead of writing an angr script from scratch, copy the relevant template, fill in the function address and parameters, and run it:

| Template file | Purpose |
|---------------|---------|
| `angr_templates/reachability.py` | Check whether a specific basic block / error path is reachable from the function entry |
| `angr_templates/taint_propagation.py` | Trace whether a value at a given address is influenced by user-controlled input (register/argument) |
| `angr_templates/switch_table.py` | Reconstruct a switch jump table that Ghidra failed to decode, enumerating all cases |
| `angr_templates/buffer_constraint.py` | Check whether a size variable can exceed a buffer's allocated length (constraint satisfiability) |

**Usage:**

1. Read the template to understand its structure:
```
read_workspace_file {"path": "angr_templates/reachability.py"}
```

2. Copy it to your function's workspace directory and fill in the parameters:
```
write_workspace_file {"path": "functions/<addr>_<name>/angr_check.py", "content": "# ... (copy template, fill in <FUNC_ADDR>, <TARGET_ADDR>, etc.)"}
```

3. Run it:
```
script_library action=run scriptName=run_angr_script parameters={"scriptPath":"functions/<addr>_<name>/angr_check.py","timeout":180}
```

### How to run angr scripts

The `run_angr_script` tool runs a Python script in a managed virtual environment (`~/.akiba/venv`, auto-created with angr pre-installed). The binary's absolute path is passed via the **`AKIBA_BINARY_PATH`** environment variable — your Python script reads it with `os.environ["AKIBA_BINARY_PATH"]`.

### When to use angr

| Scenario | Template | Why angr helps |
|----------|----------|----------------|
| **Reachability** — "is this error-handling branch reachable from the entry point?" | `reachability.py` | angr can explore paths and confirm whether a given basic block is reachable under realistic constraints. |
| **Taint propagation** — "is this value influenced by user input?" | `taint_propagation.py` | angr's symbolic execution tracks data flow through registers/memory that Ghidra's decompiler may not represent accurately. |
| **Switch table reconstruction** — Ghidra shows `if-else` chains or computed `goto` | `switch_table.py` | angr resolves the jump table and enumerates all cases, confirming Ghidra's reconstruction (or revealing missing cases). |
| **Buffer size constraints** — "can `size` exceed the buffer length?" | `buffer_constraint.py` | angr can model the constraint and check satisfiability, proving whether an overflow is reachable. |

### Important notes for angr usage

- **First run is slow** — angr installation can take 3-5 minutes on the first invocation. Subsequent runs are fast.
- **Use `auto_load_libs=False`** — loading shared libraries slows angr dramatically and is usually unnecessary for vulnerability analysis.
- **Set a realistic timeout** — symbolic execution can be slow. Use the `timeout` parameter (default 120s, max 600s). Start with 180s for non-trivial analyses.
- **Write results to the workspace** — your angr script can write findings to files (e.g. `functions/<addr>_<name>/angr_results.json`) that other agents can read later.
- **angr works on the raw binary, not Ghidra's model** — address spaces and function boundaries may differ slightly from what Ghidra shows. Cross-reference using Ghidra's image base if needed.

## Important notes

- **To persist analysis improvements, use `manage_func_vars` then re-export** — this is the correct way to improve Ghidra's decompiler output. Do NOT use `manage_func_signature` for local variables (it handles parameters/return types only).
- **After fixing variables, always re-export** — the mapping in `mapping.json` is tied to the decompiler output at export time. If you modify variables (which changes the decompiler output), the old mapping is stale.
- **The mapping is at statement level, not line level** — a single C statement (e.g. `if (a > b) goto X`) may map to multiple non-contiguous assembly addresses. Use `asmAddrs` for the complete list.
- **Always verify before concluding** — if the pseudo-C code shows a potential vulnerability, verify it against the actual assembly before recording it. The decompiler may have misrepresented the operation.
- **For switch tables** — if Ghidra failed to reconstruct a switch table, the pseudo-C code will show a series of `if-else` chains or a `goto` to a computed address. Use the assembly to identify the jump table and enumerate all cases.
