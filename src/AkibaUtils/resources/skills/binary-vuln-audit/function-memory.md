# Function Memory, Naming, and Type Refinement

## Durable notebook rule

Conversation history is not reliable for large binaries. Store function-level findings in Ghidra listing comments.

Use `script_library` → `set_get_comment`.

Read existing notes:

```json
{"action":"run","scriptName":"set_get_comment","parameters":{"action":"read","address":"<entry>","type":"ALL"}}
```

Write function-entry notes (canonical form is `action=write`; the script still accepts
`action=set` for backwards compatibility, but new calls should always use `write`):

```json
{"action":"run","scriptName":"set_get_comment","parameters":{"action":"write","address":"<entry>","type":"PLATE","comment":"AKIBA: role=<purpose>; status=<clean|candidate|confirmed|skipped>; [inputs=<sources>]; [calls=<important callees>]; [mem=<stack/heap/fmt observations>]; [confidence=<high|medium/low>]; [next=<todo>]"}}
```

Only `AKIBA:` prefix, `role=`, and `status=` are required. The bracketed fields are
OPTIONAL — omit them when you have nothing useful, do not pad them. Use `status=skipped`
for imports / PLT stubs / runtime helpers / thunks.

### `calls=` staleness warning

`calls=<callee names>` is best-effort and goes stale after `rename_function` or
function deletion — the comment lives at the address forever, but the names it
references may move or disappear. For LIVE callee info, run `get_xrefs` at audit
time rather than embedding names in the comment. If you embed names, treat them
as a snapshot only.

Add instruction-level evidence comments (EOL, free-form — no AKIBA: format required):

```json
{"action":"run","scriptName":"set_get_comment","parameters":{"action":"write","address":"<instruction-address>","type":"EOL","comment":"AKIBA: unchecked memcpy size derives from packet length"}}
```

## Naming rule

If the function name is default/generated (`FUN_*`, `sub_*`, unnamed/thunk-like), try to assign a semantic name after understanding its role.

Use `rename_function`:

```json
{"action":"run","scriptName":"rename_function","parameters":{"target":"<old-name-or-entry>","newName":"parse_request_header","returnType":"int"}}
```

Only rename when the evidence is sufficient. If uncertain, write a low-confidence comment and list what remains to verify.

## Type refinement

There are two complementary scripts:

- `alter_func_signature` — function-level edits and parameter edits (function name, return type, calling convention, varargs, no-return, inline flags, plus per-parameter set_type / rename / add / remove).
- `alter_func_var` — local variables only (set_type, rename; no delete because locals are recovered by the Ghidra decompiler and should not be removed manually).

### Parameters (function signature)

Single-parameter retype:

```json
{"action":"run","scriptName":"alter_func_signature","parameters":{"target":"parse_request_header","action":"set_param_type","paramName":"param_1","paramType":"char *"}}
```

Rename a parameter so it shows up under a semantic name in decompile and in subsequent sub-agent passes:

```json
{"action":"run","scriptName":"alter_func_signature","parameters":{"target":"parse_request_header","action":"rename_param","paramName":"param_2","newParamName":"buf"}}
```

Batch retype + rename + add — typical after a decompile shows `param_1, param_2, param_3` are actually `(ctx, buf, len)` and you want to insert an extra `len` parameter:

```json
{"action":"run","scriptName":"alter_func_signature","parameters":{"target":"parse_request_header","operations":"[{\"action\":\"set_param_type\",\"paramOrdinal\":0,\"paramType\":\"RequestCtx *\"},{\"action\":\"set_param_type\",\"paramOrdinal\":1,\"paramType\":\"uint8_t *\"},{\"action\":\"rename_param\",\"paramOrdinal\":1,\"newParamName\":\"buf\"},{\"action\":\"rename_param\",\"paramOrdinal\":2,\"newParamName\":\"len\"}]"}}
```

Change the return type:

```json
{"action":"run","scriptName":"alter_func_signature","parameters":{"target":"parse_request_header","action":"set_return_type","returnType":"int"}}
```

### Locals (function body)

Retype a local:

```json
{"action":"run","scriptName":"alter_func_var","parameters":{"target":"parse_request_header","name":"local_8","action":"set_type","type":"size_t"}}
```

Rename a local:

```json
{"action":"run","scriptName":"alter_func_var","parameters":{"target":"parse_request_header","name":"iVar1","action":"rename","newName":"bytes_consumed"}}
```

> Variable vs argument: in Ghidra `Parameter` extends `Variable` and has a stable ordinal; locals have none. Locals cannot be deleted (the decompiler regenerates them) — only `set_type` and `rename` are supported on locals, and parameter changes go through `alter_func_signature`.

## Naming clean-up for symbols and addresses

After you know what a default-named address actually holds, give it a semantic label (or remove the noise label) with `alter_label`:

```json
{"action":"run","scriptName":"alter_label","parameters":{"target":"DAT_00402000","action":"rename","newName":"packet_header_buf"}}
```

If the address has a `DAT_*`/`s_*` name AND a real Ghidra type can be applied (e.g. it's a `uint32_t` length field, or a struct member), chain a `set_data_type` call so the listing shows the typed representation:

```json
{"action":"run","scriptName":"alter_label","parameters":{"target":"packet_header_buf","action":"set_data_type","type":"uint","length":4}}
{"action":"run","scriptName":"alter_label","parameters":{"target":"DAT_00402014","action":"delete"}}
```

> `alter_label action=delete` only removes user-defined LABEL symbols. Function-entry labels, parameter / local-variable symbols, default-thunk labels, and external symbols are protected — you will get a clear error rather than a silent mis-deletion.

## Compound types: create, refine, query, delete

When the decompile reveals a struct/union that recurs across several functions, define it once via `manage_data_type action=create`, then refine it incrementally with `action=update` (no need to delete + recreate):

```json
{"action":"run","scriptName":"manage_data_type","parameters":{"name":"PacketHeader","kind":"structure","category":"/protocols","components":"[{\"name\":\"magic\",\"type\":\"uint\",\"size\":4},{\"name\":\"len\",\"type\":\"ushort\",\"size\":2},{\"name\":\"payload\",\"type\":\"uint8_t *\",\"size\":8}]"}}
```

After more analysis, swap a single component in place (preserves every other field) — `componentEdits` are applied in reverse-index order so earlier edits don't shift later ones:

```json
{"action":"run","scriptName":"manage_data_type","parameters":{"name":"PacketHeader","action":"update","componentEdits":"[{\"index\":2,\"action\":\"replace\",\"type\":\"void *\",\"name\":\"payload\"}]"}}
```

Query / rename / move / delete:

```json
{"action":"run","scriptName":"manage_data_type","parameters":{"name":"PacketHeader","action":"get"}}
{"action":"run","scriptName":"manage_data_type","parameters":{"name":"PacketHeader","action":"update","newName":"PacketHeader_v1","newCategory":"/protocols/v1"}}
{"action":"run","scriptName":"manage_data_type","parameters":{"name":"PacketHeader","action":"delete"}}
```

> `manage_data_type` is the unified tool for the previous `create_data_type` workflow plus `get` / `update` (per-component edits, rename, recategorise) / `delete`. Use `action=update componentEdits` rather than delete-then-recreate whenever possible — recreating orphans every reference in the binary and breaks `vuln_memory` lookups by type name.

## When role is unclear

Do not guess from one function body alone. Inspect:

- `get_xrefs` with `direction=both`;
- callers and callees;
- string references via `search_strings` then `get_xrefs` on string addresses;
- imports and wrapper functions;
- data flow from input to memory writes.
