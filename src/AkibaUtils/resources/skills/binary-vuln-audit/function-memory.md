# Function Memory, Naming, and Type Refinement

## Durable notebook rule

Conversation history is not reliable for large binaries. Store function-level findings in Ghidra listing comments.

Use `script_library` → `set_get_comment`.

Read existing notes:

```json
{"action":"run","scriptName":"set_get_comment","parameters":{"action":"read","address":"<entry>","type":"ALL"}}
```

Write function-entry notes:

```json
{"action":"run","scriptName":"set_get_comment","parameters":{"action":"set","address":"<entry>","type":"PLATE","comment":"AKIBA: role=<purpose>; inputs=<sources>; calls=<important callees>; mem=<stack/heap/fmt observations>; status=<clean/candidate/confirmed>; confidence=<high/medium/low>; next=<todo>"}}
```

Add instruction-level evidence comments:

```json
{"action":"run","scriptName":"set_get_comment","parameters":{"action":"set","address":"<instruction-address>","type":"EOL","comment":"AKIBA: unchecked memcpy size derives from packet length"}}
```

## Naming rule

If the function name is default/generated (`FUN_*`, `sub_*`, unnamed/thunk-like), try to assign a semantic name after understanding its role.

Use `rename_function`:

```json
{"action":"run","scriptName":"rename_function","parameters":{"target":"<old-name-or-entry>","newName":"parse_request_header","returnType":"int"}}
```

Only rename when the evidence is sufficient. If uncertain, write a low-confidence comment and list what remains to verify.

## Type refinement

When callers/callees make parameter or local variable types clear, refine them with `change_variable_type` where applicable:

```json
{"action":"run","scriptName":"change_variable_type","parameters":{"target":"parse_request_header","variable":"param_1","type":"char *"}}
```

## When role is unclear

Do not guess from one function body alone. Inspect:

- `get_xrefs` with `direction=both`;
- callers and callees;
- string references via `search_strings` then `get_xrefs` on string addresses;
- imports and wrapper functions;
- data flow from input to memory writes.
