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

1. Read existing durable notes:
   - `script_library` → `set_get_comment` with `parameters={"action":"read","address":"<entry>","type":"ALL"}`.
   - If useful AKIBA notes exist, continue from them instead of starting over.
2. Read ground-truth disassembly:
   - `script_library` → `disassemble_function` with `parameters={"target":"<function-or-address>","showBytes":true,"showComments":true}`.
   - For large functions, page with `addressAfter` from the last emitted address.
3. Use decompilation only after disassembly:
   - `decompile_function` is a readability hint, not evidence. If it disagrees with disassembly, trust disassembly.
4. Resolve function role:
   - inspect callers/callees with `get_xrefs`;
   - inspect strings with `search_strings` and then xrefs to specific string addresses;
   - consider imported APIs, memory operations, argument flow, and return values.
5. Persist semantics before moving on:
   - if the name is default/generated (`FUN_*`, `sub_*`, unnamed), rename via `rename_function` when evidence permits;
   - refine parameter/local/return types when supported by evidence;
   - write a `PRE` or `PLATE` function-entry note via `set_get_comment`;
   - add `EOL` comments at key evidence instructions.

A function is not considered analyzed until it has a durable note or an explicit reason why no useful note/name can be assigned.

## Supporting files

- `coverage.md`: function inventory, chunking, and coverage strategy.
- `function-memory.md`: naming, type refinement, and durable comments.
- `vulnerability-checklist.md`: concrete bug patterns to check.
- `report-format.md`: required final report format.
