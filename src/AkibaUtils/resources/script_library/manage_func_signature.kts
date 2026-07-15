// @name: manage_func_signature
// @author: Akiba
// @description: Read or write function signatures using C-format syntax, with full renaming support and batch mode. SINGLE MODE: pass an address and a C-format signature string (e.g. "int parse_header(char *buf, size_t len)") to atomically update the function name, return type, and all parameter names/types in one operation. Function pointer parameters are supported (e.g. "void register_cb(void (*cb)(int, void*))"). BATCH MODE: pass an 'operations' JSON array to apply multiple signature changes atomically in a single transaction — strongly recommended when modifying multiple functions. By default the function is always renamed to match the signature (forceRename=true); set forceRename=false to only rename functions with default names (e.g. FUN_401000). NOTE: if the C signature references a data type (custom struct/union/enum/typedef) that is not yet declared in the program, the write will fail — declare it first with the 'manage_data_type' tool (action=create, passing the C definition), then retry this script.
// @parameters: address (string, single mode) - Hex address inside a function (e.g. "0x401000") or function name (e.g. "main"); signature (string, single mode) - C-format function signature, e.g. "int main(int argc, char **argv)". If omitted with action=read, returns the current signature; action (string, optional) - "read" or "write" (auto-detected: "write" if signature provided, "read" otherwise); forceRename (boolean, optional, default true) - If true, always rename the function to match the signature name. If false, only rename functions with default names (RENAME_IF_DEFAULT); operations (string, optional, BATCH MODE) - JSON array of signature operations: [{"address":"0x401000","signature":"int parse_header(char *buf, size_t len)"},{"address":"0x401200","signature":"void process_data(char *data, int count)","forceRename":false}]. Each element: address (string, required), signature (string, required), forceRename (boolean, optional, overrides global setting). When 'operations' is provided, it takes precedence over single-mode parameters.
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import ghidra.app.util.cparser.C.CParserUtils
import ghidra.app.util.cparser.C.CParser
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd
import ghidra.app.cmd.function.FunctionRenameOption
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataType
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.Pointer
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
        val funcDef = parseSignatureWithFallback(program, signatureText)
        if (funcDef == null) return false

        if (scriptArgs["operations"] == null) {
            appendLine("Parsed: name=${funcDef.name}, return=${funcDef.returnType.name}, params=${funcDef.arguments.size}")
            appendLine("")
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
