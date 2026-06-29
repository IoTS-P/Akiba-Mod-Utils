# Binary Vulnerability Audit Skill

Use this skill for deep static vulnerability analysis of binaries loaded in Ghidra.

## Primary goals

Focus on memory-safety and exploitable input-handling issues:

- stack buffer overflows and stack misuse;
- format-string vulnerabilities;
- heap overflows, use-after-free, double-free, realloc misuse, and allocation-size integer overflows;
- other high-impact bugs discovered while following data flow.

`find_dangerous_calls` is only a hint source. It cannot cover all vulnerability classes. Do not rely on it as the detector.

## Mandatory function loop

For each non-trivial function, complete this loop before moving to unrelated functions:

Tool invocation rule: `disassemble_function`, `decompile_function`, `set_get_comment`, `get_xrefs`, `search_strings`, and `find_dangerous_calls` are scripts, not standalone tools. Always invoke them through the `script_library` tool with `action="run"`, `scriptName="..."`, and a nested `parameters` object.

1. Read ground-truth disassembly with existing comments included:
   - `script_library` → `disassemble_function` with `parameters={"target":"<function-or-address>","showBytes":true,"showComments":true}`.
   - `showComments=true` is the default and shows existing PRE/PLATE/EOL/POST comments in the disassembly output.
   - Use `set_get_comment` action=read only when you specifically need ALL comment types without disassembling again.
   - For large functions, page with `addressAfter` from the last emitted address.
2. Use decompilation only after disassembly:
   - `decompile_function` is a readability hint, not evidence. If it disagrees with disassembly, trust disassembly.
4. Resolve function role:
   - inspect callers/callees with `get_xrefs`;
   - inspect strings with `search_strings` and then xrefs to specific string addresses;
   - consider imported APIs, memory operations, argument flow, and return values.
5. Persist semantics before moving on:
   - if the name is default/generated (`FUN_*`, `sub_*`, unnamed), rename via `rename_function` when evidence permits;
   - refine parameter/local/return types when supported by evidence;
   - for non-trivial project-owned functions, write a `PRE` or `PLATE` function-entry note via `set_get_comment` (it accepts function names, symbols, or addresses and resolves them to canonical addresses);
   - add `EOL` comments at key evidence instructions.

Imported functions, PLT/linkage stubs, compiler/runtime helpers (for example `__stack_chk_fail`), and other non-owned library helpers do not require durable comments. Record them as skipped in the Coverage Report if they are encountered. A project-owned function is not considered analyzed until it has a durable note or an explicit reason why no useful note/name can be assigned.

## Supporting files

- `coverage.md`: function inventory, chunking, and coverage strategy.
- `function-memory.md`: naming, type refinement, and durable comments.
- `vulnerability-checklist.md`: concrete bug patterns to check.
- `report-format.md`: required final report format.
