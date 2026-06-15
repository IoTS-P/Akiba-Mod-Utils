# Coverage and Chunking Strategy

## Coverage requirement

Analyze as many non-trivial functions as possible. Do not stop after entry point and direct callees.

Prioritize functions that:

- receive or parse external input;
- perform memory allocation, copying, formatting, serialization, or parsing;
- dispatch commands or protocol messages;
- call dangerous imports or wrappers around dangerous imports;
- sit on data-flow paths from input sources to memory or command sinks.

## Large binary chunking

If the binary contains many functions, do not analyze them in a flat list.

1. Create a function inventory:
   - name/address/size;
   - obvious imports used;
   - callers/callees;
   - important strings or xrefs.
2. Group functions into chunks, for example:
   - initialization/setup;
   - network I/O handlers;
   - protocol parsers/deserializers;
   - command dispatchers/request handlers;
   - authentication/crypto;
   - file I/O/logging/persistence;
   - memory allocator wrappers/utilities;
   - cleanup/error paths.
3. Work chunk by chunk.
4. After each function, write durable comments with `set_get_comment` before moving on.
5. Before re-analyzing a function, read its existing comments.

## Avoid token waste

Do not repeatedly disassemble unrelated functions without storing conclusions. Durable comments are part of the analysis workflow, not optional documentation.
