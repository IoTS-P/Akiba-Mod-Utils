// @name: manage_func_signature
// @author: Akiba
// @description: Read or write function signatures using C-format syntax, with full renaming support and batch mode. SINGLE MODE: pass an address and a C-format signature string (e.g. "int parse_header(char *buf, size_t len)") to atomically update the function name, return type, and all parameter names/types in one operation. Function pointer parameters are supported (e.g. "void register_cb(void (*cb)(int, void*))"). BATCH MODE: pass an 'operations' JSON array to apply multiple signature changes atomically in a single transaction — strongly recommended when modifying multiple functions. By default the function is always renamed to match the signature (forceRename=true); set forceRename=false to only rename functions with default names (e.g. FUN_401000). NOTE: if the C signature references a custom struct/union/enum/typedef that is not yet declared in the program, the script will REJECT the write and list the undefined types — declare them first with the 'manage_data_type' tool (action=create, passing the C definition), then retry this script.
// @parameters: address (string, single mode) - Hex address inside a function (e.g. "0x401000") or function name (e.g. "main"); signature (string, single mode) - C-format function signature, e.g. "int main(int argc, char **argv)". If omitted with action=read, returns the current signature; action (string, optional) - "read" or "write" (auto-detected: "write" if signature provided, "read" otherwise); forceRename (boolean, optional, default true) - If true, always rename the function to match the signature name. If false, only rename functions with default names (RENAME_IF_DEFAULT); operations (string, optional, BATCH MODE) - JSON array of signature operations: [{"address":"0x401000","signature":"int parse_header(char *buf, size_t len)"},{"address":"0x401200","signature":"void process_data(char *data, int count)","forceRename":false}]. Each element: address (string, required), signature (string, required), forceRename (boolean, optional, overrides global setting). When 'operations' is provided, it takes precedence over single-mode parameters.
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import ghidra.app.util.cparser.C.CParserUtils
import ghidra.app.util.cparser.C.CParser
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd
import ghidra.app.cmd.function.FunctionRenameOption
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Composite
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType

class ManageFuncSignature : AkibaScript() {

    // Hint shown when a signature write fails because a referenced data type
    // does not exist in the program yet.
    private val UNDEFINED_TYPE_HINT =
        "HINT: If the failure is caused by an undefined data type referenced in the signature " +
        "(a custom struct/union/enum/typedef that is not declared yet), declare it first with the " +
        "'manage_data_type' tool (action=create, passing a C definition), then retry this signature."

    override suspend fun execute() {

        val rawOps = (scriptArgs["operations"] as? String)?.takeIf { it.isNotBlank() }

        if (rawOps != null) {
            doBatch(program!!, rawOps)
        } else {
            doSingle(program!!)
        }
    }

    // ── Single mode ───────────────────────────────────────────────────────

    private fun doSingle(program: ghidra.program.model.listing.Program) {
        val addressStr = scriptArgs["address"] as? String
            ?: run { appendLine("Error: 'address' parameter is required (hex address or function name)"); return }
        val signature = (scriptArgs["signature"] as? String)?.takeIf { it.isNotBlank() }
        val forceRename = (scriptArgs["forceRename"] as? Boolean) ?: true
        val action = ((scriptArgs["action"] as? String)?.lowercase())
            ?: if (signature != null) "write" else "read"

        val func = resolveFunction(program, addressStr)
        if (func == null) {
            appendLine("Error: no function found at or containing '$addressStr'")
            return
        }

        when (action) {
            "read" -> doRead(func)
            "write" -> {
                if (signature == null) {
                    appendLine("Error: 'signature' parameter is required for action=write")
                    return
                }
                val ok = doWrite(program, func, signature, forceRename)
                if (ok) {
                    appendLine("")
                    appendLine("Result: 1 function updated.")
                }
            }
            else -> appendLine("Error: invalid action '$action' (expected 'read' or 'write')")
        }
    }

    // ── Batch mode ────────────────────────────────────────────────────────

    @Suppress("UNCHECKED_CAST")
    private fun doBatch(program: ghidra.program.model.listing.Program, rawOps: String) {
        val globalForceRename = (scriptArgs["forceRename"] as? Boolean) ?: true

        val ops: List<Map<String, Any?>> = try {
            com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(rawOps, List::class.java)
                .map { (it as? Map<String, Any?>) ?: emptyMap() }
        } catch (e: Exception) {
            appendLine("Error: 'operations' is not a valid JSON array: ${e.message}")
            return
        }

        if (ops.isEmpty()) {
            appendLine("Error: 'operations' array is empty")
            return
        }

        appendLine("=== Batch Function Signature Update ===")
        appendLine("Operations: ${ops.size}")
        appendLine("Force rename (global): $globalForceRename")
        appendLine("")

        val txId = program.startTransaction("manage_func_signature batch (${ops.size} op(s))")
        var committed = false
        var okCount = 0
        val failures = mutableListOf<String>()

        try {
            for ((idx, op) in ops.withIndex()) {
                val addressStr = op["address"] as? String
                if (addressStr.isNullOrBlank()) {
                    failures.add("[#$idx] missing 'address'"); continue
                }
                val signature = (op["signature"] as? String)?.takeIf { it.isNotBlank() }
                if (signature == null) {
                    failures.add("[#$idx] missing 'signature'"); continue
                }
                val forceRename = (op["forceRename"] as? Boolean) ?: globalForceRename

                val func = resolveFunction(program, addressStr)
                if (func == null) {
                    failures.add("[#$idx] no function at '$addressStr'")
                    continue
                }

                val oldName = func.name
                val ok = doWrite(program, func, signature, forceRename)
                if (ok) {
                    val newName = func.name
                    val renamed = newName != oldName
                    appendLine("[#$idx] OK: $addressStr ${if (renamed) "$oldName -> $newName" else newName}")
                    okCount++
                } else {
                    failures.add("[#$idx] write failed at '$addressStr'")
                }
            }

            committed = failures.isEmpty()

            appendLine("")
            appendLine("Summary: ${ops.size} op(s), $okCount applied, ${failures.size} failed")
            if (failures.isNotEmpty()) {
                appendLine("Failures:")
                failures.forEach { appendLine("  - $it") }
                appendLine("")
                appendLine(UNDEFINED_TYPE_HINT)
            }
        } catch (e: Exception) {
            appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, committed)
        }
    }

    // ── Read mode ─────────────────────────────────────────────────────────

    private fun doRead(func: Function) {
        appendLine("=== Function Signature (Read) ===")
        appendLine("Name: ${func.name}")
        appendLine("Entry: ${func.entryPoint}")
        appendLine("Body: ${func.body.minAddress} - ${func.body.maxAddress}")
        appendLine("Size: ${func.body.numAddresses} bytes")
        appendLine("Calling convention: ${func.callingConventionName}")
        appendLine("Is thunk: ${func.isThunk}")
        appendLine("Has varargs: ${func.hasVarArgs()}")
        appendLine("No return: ${func.hasNoReturn()}")
        appendLine("Inline: ${func.isInline}")
        appendLine("")
        appendLine("C Signature:")
        appendLine("  ${func.getPrototypeString(true, false)}")
        appendLine("")

        val params = func.parameters
        if (params.isNotEmpty()) {
            appendLine("Parameters (${params.size}):")
            for (p in params) {
                val auto = if (p.isAutoParameter) " [auto]" else ""
                appendLine("  [${p.ordinal}] ${p.name}: ${p.dataType.name}  (storage: ${p.variableStorage})$auto")
            }
        }

        appendLine("")
        appendLine("Return type: ${func.returnType.name}")
        appendLine("Return storage: ${func.getReturn().variableStorage}")
        appendLine("")
        appendLine("To modify: pass this address with signature=\"<new C signature>\"")
        appendLine("To batch-modify: pass operations=\"[{\\\"address\\\":\\\"0x401000\\\",\\\"signature\\\":\\\"...\\\"},...]\"")
    }

    // ── Write mode (returns true on success) ──────────────────────────────

    private fun doWrite(
        program: ghidra.program.model.listing.Program,
        func: Function,
        signatureText: String,
        forceRename: Boolean
    ): Boolean {
        val oldSignature = func.getPrototypeString(true, false)
        val oldName = func.name

        if (scriptArgs["operations"] == null) {
            // Single mode: show detailed output
            appendLine("=== Function Signature (Write) ===")
            appendLine("Address: ${func.entryPoint}")
            appendLine("Old signature: $oldSignature")
            appendLine("New signature: $signatureText")
            appendLine("Force rename: $forceRename")
            appendLine("")
        }

        // ── Parse the C signature string ─────────────────────────────────
        // CParserUtils.parseSignature pre-splits the signature text, which
        // breaks function pointer parameters like void (*cb)(void*,int).
        // We detect ".conflict" types in the result and fall back to the
        // full C parser (CParser.parse) which handles function pointers
        // natively.
        //
        // Pre-normalize: if the return type is a pointer and the '*' is
        // adjacent to the function name (e.g. "void*foo(...)" or
        // "void *foo(...)"), CParserUtils may misparse the '*' as part of
        // the function name. We insert a space between the '*' and the
        // function name to prevent this.
        val normalizedSig = normalizeSignature(signatureText)
        val funcDef = parseSignatureWithFallback(program, normalizedSig)
        if (funcDef == null) return false

        // Detect and fix the asterisk-in-name issue post-parse as well:
        // even after normalization, some CParser code paths may still
        // include the '*' in the function name.
        if (funcDef.name.startsWith("*")) {
            val cleanName = funcDef.name.trimStart('*').trim()
            if (cleanName.isNotEmpty()) {
                if (scriptArgs["operations"] == null) {
                    appendLine("Note: corrected function name '${funcDef.name}' -> '$cleanName' (stripped leading '*').")
                }
                funcDef.setName(cleanName)
            }
        }

        if (scriptArgs["operations"] == null) {
            appendLine("Parsed: name=${funcDef.name}, return=${funcDef.returnType.name}, params=${funcDef.arguments.size}")
            appendLine("")
        }

        // ── Validate: reject auto-created empty struct/union types ────────
        // CParser silently creates empty StructureDataType / UnionDataType
        // placeholders for unknown struct/union names in the signature. These
        // are 0-byte or 0-component types with no fields — applying them would
        // pollute the DTM with empty stubs. We detect and reject them here,
        // telling the LLM to declare the type first via manage_data_type.
        val undefinedTypes = findUndefinedCompositeTypes(program, funcDef)
        if (undefinedTypes.isNotEmpty()) {
            val isSingle = scriptArgs["operations"] == null
            if (isSingle) {
                appendLine("Error: the signature references ${undefinedTypes.size} data type(s) " +
                    "that are not defined in the program:")
                for (name in undefinedTypes) {
                    appendLine("  - $name (empty struct/union — not yet declared)")
                }
                appendLine("")
                appendLine(UNDEFINED_TYPE_HINT)
            }
            return false
        }

        // ── Apply the signature ──────────────────────────────────────────
        // Use the full constructor to control FunctionRenameOption:
        //   RENAME          — always rename (forceRename=true)
        //   RENAME_IF_DEFAULT — only rename default names like FUN_xxx (forceRename=false)
        val renameOption = if (forceRename) FunctionRenameOption.RENAME
                           else FunctionRenameOption.RENAME_IF_DEFAULT

        val cmd = ApplyFunctionSignatureCmd(
            func.entryPoint,
            funcDef,
            SourceType.USER_DEFINED,
            false,   // preserveCallingConvention
            false,   // applyEmptyComposites
            DataTypeConflictHandler.REPLACE_HANDLER, // replace existing types to avoid ".conflict" suffixes
            renameOption
        )

        val ok = try {
            cmd.applyTo(program, taskGlobalMonitor)
        } catch (e: Exception) {
            if (scriptArgs["operations"] == null) {
                appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
                appendLine(UNDEFINED_TYPE_HINT)
            }
            return false
        }

        if (!ok) {
            if (scriptArgs["operations"] == null) {
                appendLine("Error: ApplyFunctionSignatureCmd failed: ${cmd.statusMsg}")
                appendLine(UNDEFINED_TYPE_HINT)
            }
            return false
        }

        // ── Report result (single mode only — batch mode reports in caller)
        if (scriptArgs["operations"] == null) {
            val newSignature = func.getPrototypeString(true, false)
            val newName = func.name
            val renamed = newName != oldName

            appendLine("Signature applied successfully!")
            if (renamed) {
                appendLine("  Function renamed: $oldName -> $newName")
            } else {
                appendLine("  Function name unchanged ($newName)")
            }
            appendLine("  New signature: $newSignature")
            appendLine("  Calling convention: ${func.callingConventionName}")

            val params = func.parameters
            if (params.isNotEmpty()) {
                appendLine("")
                appendLine("Parameters (${params.size}):")
                for (p in params) {
                    val auto = if (p.isAutoParameter) " [auto]" else ""
                    appendLine("  [${p.ordinal}] ${p.name}: ${p.dataType.name}  (storage: ${p.variableStorage})$auto")
                }
            }
        }

        return true
    }

    // ── Helpers: validate data types ──────────────────────────────────────

    /**
     * Normalize a C function signature string to prevent CParser from
     * misinterpreting a pointer-return '*' as part of the function name.
     *
     * Problem: "void *foo(...)" — the '*' is adjacent to the function name
     * (no space between them). CParser may include the '*' in the function
     * name, producing a function named "*foo" instead of "foo".
     *
     * Fix: insert a space between the '*' and the function name:
     *   "void *foo(...)"  → "void * foo(...)"
     *   "void **foo(...)" → "void ** foo(...)"
     *   "void * foo(...)" → no change (already separated)
     *
     * We only target the return-type position (before the first '('),
     * and skip function pointer parameters like "void (*cb)(...)" where
     * the '*' is preceded by '('.
     */
    private fun normalizeSignature(signatureText: String): String {
        val s = signatureText.trim()
        val firstParen = s.indexOf('(')
        if (firstParen < 0) return s
        val beforeParen = s.substring(0, firstParen)

        // Match: one or more '*' immediately followed by an identifier char
        // (letter or underscore), where the '*' is NOT preceded by '('.
        // This catches "void *foo" but not "void * foo" (already separated)
        // and not "(*cb)" (preceded by '(').
        val pattern = Regex("""(?<!\()\*+(\w)""")
        val match = pattern.find(beforeParen)
        if (match == null) return s

        val fixedBefore = pattern.replace(beforeParen) { m ->
            val stars = m.groupValues[0].takeWhile { it == '*' }
            val identChar = m.groupValues[1]
            "$stars $identChar"
        }
        val fixed = fixedBefore + s.substring(firstParen)

        if (fixed != s && scriptArgs["operations"] == null) {
            appendLine("Note: normalized signature '$s' -> '$fixed' (separated '*' from function name).")
        }
        return fixed
    }

    /**
     * Check all argument and return types in the parsed function definition
     * for composite (struct/union) types that are empty (0 components).
     *
     * CParser auto-creates empty StructureDataType placeholders for unknown
     * struct/union names. These have 0 components and are NOT pre-existing
     * user-defined types. We detect them by:
     *   1. The type is a Composite (Structure or Union)
     *   2. It has 0 components (empty body)
     *   3. It was NOT in the DTM before parsing (we check category path —
     *      auto-created types land in ROOT with no prior definition)
     *
     * Returns the set of undefined type names found, or empty set if all
     * types are properly defined.
     */
    private fun findUndefinedCompositeTypes(
        program: ghidra.program.model.listing.Program,
        funcDef: FunctionDefinitionDataType
    ): Set<String> {
        val undefined = mutableSetOf<String>()

        // Check return type
        checkForEmptyComposite(funcDef.returnType, undefined)

        // Check all argument types
        for (arg in funcDef.arguments) {
            checkForEmptyComposite(arg.dataType, undefined)
        }

        return undefined
    }

    /**
     * Recursively check a DataType for empty composites.
     * Drills into pointers and typedefs to find the base type.
     */
    private fun checkForEmptyComposite(dt: DataType, undefined: MutableSet<String>) {
        when (dt) {
            is Composite -> {
                // An empty composite (0 components) is a placeholder created
                // by CParser for an unknown struct/union name. Real user-defined
                // types always have at least 1 component (or are intentionally
                // empty but that's extremely rare — we treat it as undefined).
                if (dt.numComponents == 0) {
                    undefined.add(dt.name)
                }
            }
            is Pointer -> {
                // Check the pointed-to type (e.g. MyStruct * → check MyStruct)
                val base = dt.dataType
                if (base != null) {
                    checkForEmptyComposite(base, undefined)
                }
            }
            is ghidra.program.model.data.TypeDef -> {
                // Check the underlying type
                checkForEmptyComposite(dt.dataType, undefined)
            }
            is ghidra.program.model.data.Array -> {
                checkForEmptyComposite(dt.dataType, undefined)
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Parse a C-format signature string into a FunctionDefinitionDataType.
     *
     * First tries CParserUtils.parseSignature (handles function-name splitting
     * for names with spaces/special chars). If the result contains ".conflict"
     * types — indicating that function pointer parameters were not parsed
     * correctly by the pre-splitting approach — falls back to the full C parser
     * (CParser.parse) which handles function pointers natively.
     */
    private fun parseSignatureWithFallback(
        program: ghidra.program.model.listing.Program,
        signatureText: String
    ): FunctionDefinitionDataType? {
        val dtm = program.dataTypeManager
        val isSingle = scriptArgs["operations"] == null

        // ── Attempt 1: CParserUtils.parseSignature ──
        val funcDef = try {
            CParserUtils.parseSignature(null, program, signatureText, false)
        } catch (e: Exception) {
            val msg = CParserUtils.handleParseProblem(e, signatureText) ?: e.message
            if (isSingle) {
                appendLine("Error: failed to parse signature: $msg")
                appendLine(UNDEFINED_TYPE_HINT)
            }
            return null
        }

        if (funcDef == null) {
            if (isSingle) {
                appendLine("Error: failed to parse signature (CParserUtils returned null)")
                appendLine("  Ensure the signature is valid C syntax, e.g.:")
                appendLine("  int main(int argc, char **argv)")
            }
            return null
        }

        // Check for .conflict types in arguments (function pointer parsing issue)
        if (hasConflictTypes(funcDef)) {
            if (isSingle) {
                appendLine("Note: type conflict detected in parsed signature " +
                    "(likely a function pointer parameter).")
                appendLine("  Retrying with full C parser (CParser.parse)...")
            }
            val fallback = parseWithFullCParser(dtm, signatureText)
            if (fallback != null) {
                if (isSingle) appendLine("  Full C parser succeeded.")
                return fallback
            }
            if (isSingle) {
                appendLine("  Full C parser also failed; proceeding with original parse " +
                    "(function pointer types may be incorrect).")
            }
        }

        return funcDef
    }

    /** Check whether any argument's data type contains a ".conflict" type. */
    private fun hasConflictTypes(funcDef: FunctionDefinitionDataType): Boolean {
        for (arg in funcDef.arguments) {
            if (containsConflictType(arg.dataType)) return true
        }
        return false
    }

    /** Recursively check if a DataType (or its pointer target) has ".conflict" in its name. */
    private fun containsConflictType(dt: DataType): Boolean {
        if (dt.name.contains(".conflict")) return true
        if (dt is Pointer) {
            val target = dt.dataType
            if (target != null && target.name.contains(".conflict")) return true
        }
        return false
    }

    /**
     * Parse a full C function declaration using CParser directly.
     * CParser is a complete C grammar parser that handles function pointer
     * parameters natively, unlike CParserUtils.parseSignature which pre-splits
     * the signature and breaks on nested parentheses.
     */
    private fun parseWithFullCParser(
        dtm: ghidra.program.model.data.DataTypeManager,
        signatureText: String
    ): FunctionDefinitionDataType? {
        val isSingle = scriptArgs["operations"] == null
        // CParser expects a semicolon-terminated declaration
        val text = signatureText.trim().let { if (it.endsWith(";")) it else "$it;" }
        val parser = CParser(dtm)
        return try {
            val parsed = parser.parse(text)
            if (parsed is FunctionDefinitionDataType) {
                return parsed
            }
            // If parse() didn't return a FunctionDefinitionDataType directly,
            // check the getFunctions() map.
            val funcs = parser.getFunctions()
            for (value in funcs.values) {
                if (value is FunctionDefinitionDataType) return value
            }
            null
        } catch (e: Exception) {
            if (isSingle) {
                appendLine("  CParser fallback failed: ${e.message}")
            }
            null
        }
    }

    private fun resolveFunction(
        program: ghidra.program.model.listing.Program,
        target: String
    ): Function? {
        val fm = program.functionManager

        // Try as function name first
        val iter = fm.getFunctions(true)
        while (iter.hasNext()) {
            val f = iter.next()
            if (f.name.equals(target, ignoreCase = true)) return f
        }

        // Try as address
        val addr = try { program.addressFactory.getAddress(target) } catch (_: Exception) { null }
        if (addr != null) {
            return fm.getFunctionAt(addr) ?: fm.getFunctionContaining(addr)
        }

        return null
    }
}
