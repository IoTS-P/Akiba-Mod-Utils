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

`calls=<callee names>` is best-effort and goes stale after function renaming or
deletion — the comment lives at the address forever, but the names it
references may move or disappear. For LIVE callee info, run `get_xrefs` at audit
time rather than embedding names in the comment. If you embed names, treat them
as a snapshot only.

Add instruction-level evidence comments (EOL, free-form — no AKIBA: format required):

```json
{"action":"run","scriptName":"set_get_comment","parameters":{"action":"write","address":"<instruction-address>","type":"EOL","comment":"AKIBA: unchecked memcpy size derives from packet length"}}
```

## Naming rule

If the function name is default/generated (`FUN_*`, `sub_*`, unnamed/thunk-like), try to assign a semantic name after understanding its role.

Use `manage_func_signature` — it renames the function AND fixes the parameter names/types and return type in a single C-format signature write:

```json
{"action":"run","scriptName":"manage_func_signature","parameters":{"address":"<old-name-or-entry>","signature":"int parse_request_header(char *buf, size_t len)"}}
```

Read mode prints the current prototype so you can decide what to change:

```json
{"action":"run","scriptName":"manage_func_signature","parameters":{"address":"<name-or-entry>","action":"read"}}
```

For a non-default name you want to replace, pass `forceRename=true` (the default) to `manage_func_signature` — it will always rename to match the signature name. Only rename when the evidence is sufficient. If uncertain, write a low-confidence comment and list what remains to verify.

## Type refinement

The unified signature tool is `manage_func_signature` — given a C-format signature it atomically renames the function, sets the return type, and sets every parameter's name AND data type in ONE call. Use it for all rename + parameter + return-type work. If the C signature references a data type that is not yet declared (custom struct/union/enum/typedef), declare it first with `manage_data_type action=create`, then retry.

- `manage_func_signature` — rename + parameter names/types + return type from one C signature string, e.g. `signature="jint parse_header(JNIEnv *ctx, jobject this, jbyteArray buf, jint len)"`. Supports function pointer parameters (e.g. `void register_cb(void (*cb)(int, void*))`). Batch mode via `operations` JSON array applies multiple signature changes atomically.
- `manage_data_type` — create / get / search / delete custom struct/union/enum/typedef using C-format definitions (e.g. `struct PacketHeader { uint32_t magic; uint16_t len; };`).

### Parameters (function signature)

Retype + rename all parameters in one call (preferred — no per-parameter plumbing):

```json
{"action":"run","scriptName":"manage_func_signature","parameters":{"address":"parse_request_header","signature":"int process(RequestCtx *ctx, uint8_t *buf, size_t len)"}}
```

Rename a default parameter to `unknown_<n>` when you cannot infer a semantic name — still inside the signature:

```json
{"action":"run","scriptName":"manage_func_signature","parameters":{"address":"parse_request_header","signature":"int process(RequestCtx *ctx, uint8_t *unknown_1, size_t len)"}}
```

## Naming clean-up for symbols and addresses

After you know what a default-named address actually holds, give it a semantic label with `set_get_comment` (PLATE or PRE comment) describing its role. To apply a Ghidra data type at an address, use `define_undefine_data`:

```json
{"action":"run","scriptName":"define_undefine_data","parameters":{"address":"0x00402000","action":"define","type":"int","length":4}}
```

## Compound types: create, query, search, delete

When the decompile reveals a struct/union that recurs across several functions, define it once via `manage_data_type action=create` using a C-format definition:

```json
{"action":"run","scriptName":"manage_data_type","parameters":{"action":"create","definition":"struct PacketHeader { uint32_t magic; uint16_t len; uint8_t *payload; };","category":"/protocols"}}
```

Query a type by name to inspect its layout:

```json
{"action":"run","scriptName":"manage_data_type","parameters":{"action":"get","name":"PacketHeader"}}
```

Search for types by name or field name (supports empty query to list all types; user-defined types are shown first):

```json
{"action":"run","scriptName":"manage_data_type","parameters":{"action":"search","query":"Packet","type":"struct","limit":50}}
```

Delete a type:

```json
{"action":"run","scriptName":"manage_data_type","parameters":{"action":"delete","name":"PacketHeader"}}
```

> `manage_data_type` supports C-format definitions for struct, union, enum, and typedef. Nested structures and references to other defined or built-in types are supported. To update an existing type, simply re-create it with the same name (REPLACE_HANDLER replaces the old definition).

## When role is unclear

Do not guess from one function body alone. Inspect:

- `get_xrefs` with `direction=both`;
- callers and callees;
- string references via `search_strings` then `get_xrefs` on string addresses;
- imports and wrapper functions;
- data flow from input to memory writes.
