// @name: manage_func_vars
// @author: Akiba
// @description: Rename and/or retype LOCAL variables inside a function body (NOT parameters — use manage_func_signature for parameters). Requires decompilation to access the decompiler's high-level variable model. Supports two modes: (1) Single — rename/retype one variable; (2) Batch — apply multiple variable changes in one decompilation pass (recommended when modifying several locals in the same function, as it avoids repeated decompilation). The variable is identified by its current name (e.g. "local_8", "iVar1") as shown in the decompiler output. Only fixed-length data types are supported. Type syntax supports: simple types (int, char, long, size_t, byte, void), pointer types (char*, void**, MyStruct*), and array types (byte[8], char[16]). If the data type size differs from the current size, Ghidra will attempt to grow/shrink the storage allocation.
// @parameters: address (string, required) - Hex address inside the function (e.g. "0x401000") or function name (e.g. "main"); name (string, for single mode) - Current local variable name to modify; newName (string, optional, for single mode) - New variable name (if omitted, name is unchanged); newType (string, optional, for single mode) - New data type name (e.g. "int", "char*", "size_t", "MyStruct*"). If omitted, type is unchanged. The type must already exist in the program's data type manager; operations (string, optional, BATCH MODE) - JSON array of variable operations: [{"name":"local_8","newName":"rc"},{"name":"iVar1","newType":"size_t"},{"name":"local_10","newName":"buf","newType":"char*"}]. Each element: name (string, required), newName (string, optional), newType (string, optional). When 'operations' is provided, single-mode parameters are ignored
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileOptions
import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.pcode.HighSymbol
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TimeoutTaskMonitor
import java.util.concurrent.TimeUnit

class ManageFuncVars : AkibaScript() {

    override suspend fun execute() {
        val program = this.program ?: run { appendLine("Error: no program loaded"); return }
        val addressStr = scriptArgs["address"] as? String
            ?: run { appendLine("Error: 'address' parameter is required (hex address or function name)"); return }

        // Resolve function
        val func = resolveFunction(program, addressStr)
        if (func == null) {
            appendLine("Error: no function found at or containing '$addressStr'")
            return
        }

        val rawOps = (scriptArgs["operations"] as? String)?.takeIf { it.isNotBlank() }
        if (rawOps != null) {
            doBatch(program, func, rawOps)
        } else {
            doSingle(program, func)
        }
    }

    // ── Single mode ───────────────────────────────────────────────────────

    private fun doSingle(program: ghidra.program.model.listing.Program, func: Function) {
        val varName = scriptArgs["name"] as? String
            ?: run { appendLine("Error: 'name' parameter is required for single mode"); return }
        val newName = scriptArgs["newName"] as? String
        val newType = scriptArgs["newType"] as? String

        if (newName == null && newType == null) {
            appendLine("Error: at least one of 'newName' or 'newType' must be provided")
            return
        }

        appendLine("=== Manage Function Variables (Single) ===")
        appendLine("Function: ${func.name} @ ${func.entryPoint}")
        appendLine("Variable: $varName")
        if (newName != null) appendLine("New name: $newName")
        if (newType != null) appendLine("New type: $newType")
        appendLine("")

        val ok = applyVarChange(program, func, varName, newName, newType)
        if (ok) {
            appendLine("")
            appendLine("Result: 1 variable updated.")
        }
    }

    // ── Batch mode ────────────────────────────────────────────────────────

    @Suppress("UNCHECKED_CAST")
    private fun doBatch(program: ghidra.program.model.listing.Program, func: Function, rawOps: String) {
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

        appendLine("=== Manage Function Variables (Batch) ===")
        appendLine("Function: ${func.name} @ ${func.entryPoint}")
        appendLine("Operations: ${ops.size}")
        appendLine("")

        // Decompile ONCE and reuse the HighFunction for all operations.
        // This avoids repeated decompilation and the "renumbering" issue
        // that occurs when each rename triggers a fresh decompile.
        val highFunc = decompileAndGetHighFunction(program, func)
        if (highFunc == null) {
            appendLine("Error: failed to decompile function for batch mode")
            return
        }

        val txId = program.startTransaction("manage_func_vars batch (${ops.size} op(s))")
        var committed = false
        var okCount = 0
        val failures = mutableListOf<String>()

        try {
            for ((idx, op) in ops.withIndex()) {
                val varName = op["name"] as? String
                if (varName.isNullOrBlank()) {
                    failures.add("[#$idx] missing 'name'"); continue
                }
                val newName = op["newName"] as? String
                val newType = op["newType"] as? String
                if (newName == null && newType == null) {
                    failures.add("[#$idx] at least one of 'newName' or 'newType' required")
                    continue
                }

                val ok = applyVarChangeWithHighFunc(program, highFunc, func, varName, newName, newType, idx)
                if (ok) okCount++ else failures.add("[#$idx] failed on '$varName'")
            }
            committed = failures.isEmpty()

            appendLine("")
            appendLine("Summary: ${ops.size} op(s), $okCount applied, ${failures.size} failed")
            if (failures.isNotEmpty()) {
                appendLine("Failures:")
                failures.forEach { appendLine("  - $it") }
            }
        } catch (e: Exception) {
            appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, committed)
        }
    }

    // ── Core: apply a single variable change ──────────────────────────────

    private fun applyVarChange(
        program: ghidra.program.model.listing.Program,
        func: Function,
        varName: String,
        newName: String?,
        newType: String?
    ): Boolean {
        val highFunc = decompileAndGetHighFunction(program, func)
        if (highFunc == null) {
            appendLine("Error: failed to decompile function")
            return false
        }
        return applyVarChangeWithHighFunc(program, highFunc, func, varName, newName, newType, null)
    }

    private fun applyVarChangeWithHighFunc(
        program: ghidra.program.model.listing.Program,
        highFunc: ghidra.program.model.pcode.HighFunction,
        func: Function,
        varName: String,
        newName: String?,
        newType: String?,
        batchIdx: Int?
    ): Boolean {
        val prefix = batchIdx?.let { "[#$it] " } ?: ""

        // Find the HighSymbol for the local variable by name.
        // Only look at LOCAL symbols, not parameters (parameters are managed
        // by manage_func_signature).
        val symbolMap = highFunc.localSymbolMap
        val symbols = symbolMap.symbols
        var targetSymbol: HighSymbol? = null
        for (sym in symbols) {
            if (sym.isParameter) continue
            if (sym.name == varName) {
                targetSymbol = sym
                break
            }
        }

        if (targetSymbol == null) {
            appendLine("${prefix}Error: local variable '$varName' not found in function '${func.name}'")
            // List available local variable names to help the LLM.
            // symbolMap.symbols returns an Iterator (single-use), and the
            // Iterator above has already been consumed, so we fetch a fresh one.
            val available = mutableListOf<String>()
            for (sym in symbolMap.symbols) {
                if (!sym.isParameter) {
                    val n = sym.name
                    if (n != null) available.add(n)
                }
            }
            if (available.isNotEmpty()) {
                appendLine("${prefix}  Available local variables: ${available.distinct().joinToString(", ")}")
            }
            return false
        }

        // Resolve the new data type (if specified)
        var resolvedType: DataType? = null
        if (newType != null) {
            resolvedType = resolveDataType(program, newType)
            if (resolvedType == null) {
                appendLine("${prefix}Error: data type '$newType' not found in the program's data type manager")
                appendLine("${prefix}  Supported syntax: simple types (int, char, long, size_t, ...),")
                appendLine("${prefix}  pointer types (char*, void**, MyStruct*), array types (byte[8], char[16]).")
                appendLine("${prefix}  Use manage_data_type action=search to find available base types.")
                return false
            }
        }

        // Apply the change via HighFunctionDBUtil.updateDBVariable
        // This is the canonical Ghidra API for renaming/retyping local variables.
        // It writes directly to the program database and updates all references.
        try {
            HighFunctionDBUtil.updateDBVariable(
                targetSymbol,
                newName,       // null = keep current name
                resolvedType,  // null = keep current type
                SourceType.USER_DEFINED
            )
            val changes = mutableListOf<String>()
            if (newName != null) changes.add("name: $varName -> $newName")
            if (newType != null) changes.add("type: -> ${resolvedType!!.name}")
            appendLine("${prefix}OK: $varName (${changes.joinToString(", ")})")
            return true
        } catch (e: ghidra.util.exception.InvalidInputException) {
            appendLine("${prefix}Error: invalid input for '$varName': ${e.message}")
            return false
        } catch (e: ghidra.util.exception.DuplicateNameException) {
            appendLine("${prefix}Error: name '$newName' already exists in function '${func.name}'")
            return false
        } catch (e: UnsupportedOperationException) {
            appendLine("${prefix}Error: unsupported variable type for '$varName': ${e.message}")
            return false
        } catch (e: Exception) {
            appendLine("${prefix}Error: ${e.javaClass.simpleName}: ${e.message}")
            return false
        }
    }

    // ── Decompilation helper ──────────────────────────────────────────────

    private fun decompileAndGetHighFunction(
        program: ghidra.program.model.listing.Program,
        func: Function
    ): ghidra.program.model.pcode.HighFunction? {
        val decompiler = DecompInterface()
        decompiler.toggleSyntaxTree(true)
        decompiler.toggleCCode(true)
        decompiler.toggleParamMeasures(false)

        if (!decompiler.openProgram(program)) {
            appendLine("Error: failed to open program in decompiler: ${decompiler.lastMessage}")
            return null
        }

        try {
            val monitor = TimeoutTaskMonitor.timeoutIn(60, TimeUnit.SECONDS)
            val result = decompiler.decompileFunction(func, 60, monitor)
            if (result == null || !result.decompileCompleted()) {
                appendLine("Error: decompilation failed: ${result?.errorMessage ?: "unknown"}")
                return null
            }
            return result.getHighFunction()
        } finally {
            decompiler.dispose()
        }
    }

    // ── Data type resolution ──────────────────────────────────────────────

    /**
     * Resolve a C-style type expression to a Ghidra [DataType].
     *
     * Supports:
     * - Simple types: "int", "char", "byte", "long", "void", "size_t", ...
     * - Pointer types: "char*", "void**", "int*", "MyStruct*"
     * - Array types:  "byte[8]", "char[16]", "int[4]"
     * - Mixed: "char*[10]" (array of pointers), "int**" (pointer to pointer)
     *
     * Pointer and array types are NOT stored in the DTM's category tree —
     * they are constructed dynamically via [PointerDataType.getPointer] and
     * [ArrayDataType].  This method parses the type expression and constructs
     * the appropriate type.
     */
    private fun resolveDataType(
        program: ghidra.program.model.listing.Program,
        typeName: String
    ): DataType? {
        val dtm = program.dataTypeManager
        return resolveTypeExpr(dtm, typeName.trim())
    }

    /**
     * Recursively resolve a type expression that may end with `*` (pointer)
     * or `[N]` (array) suffixes.
     */
    private fun resolveTypeExpr(
        dtm: ghidra.program.model.data.DataTypeManager,
        expr: String
    ): DataType? {
        val trimmed = expr.trim()

        // ── Array suffix: type[N] ──
        // Match the LAST [N] at the end of the string.
        val arrayMatch = Regex("^(.+?)\\[(\\d+)\\]$").find(trimmed)
        if (arrayMatch != null) {
            val baseExpr = arrayMatch.groupValues[1].trim()
            val count = arrayMatch.groupValues[2].toIntOrNull() ?: return null
            if (count <= 0) return null
            val baseType = resolveTypeExpr(dtm, baseExpr) ?: return null
            return ArrayDataType(baseType, count)
        }

        // ── Pointer suffix: type* ──
        // Strip trailing `*` (possibly multiple) one at a time so that
        // "int**" becomes pointer(pointer(int)).
        if (trimmed.endsWith("*")) {
            val baseExpr = trimmed.dropLast(1).trim()
            // "void*" needs special handling — void is not a normal data type
            // but PointerDataType.VOID is a built-in.
            if (baseExpr.equals("void", ignoreCase = true)) {
                return PointerDataType.getPointer(ghidra.program.model.data.VoidDataType.dataType, dtm)
            }
            val baseType = resolveTypeExpr(dtm, baseExpr) ?: return null
            return PointerDataType.getPointer(baseType, dtm)
        }

        // ── Base type lookup ──
        return findBaseType(dtm, trimmed)
    }

    /**
     * Find a base (non-pointer, non-array) type by name in the DTM.
     * Handles common aliases and built-in types.
     */
    private fun findBaseType(
        dtm: ghidra.program.model.data.DataTypeManager,
        name: String
    ): DataType? {
        // Try root category first
        dtm.getDataType(CategoryPath.ROOT, name)?.let { return it }

        // Search all categories
        searchCategory(dtm.rootCategory, name)?.let { return it }

        // ── Built-in type aliases ──
        // Ghidra's built-in types may use different names than what the LLM
        // (trained on C code) expects.  Map common aliases.
        val alias = when (name.lowercase()) {
            "byte" -> "byte"           // Ghidra built-in
            "char" -> "char"
            "uchar", "unsigned char" -> "uchar"
            "short" -> "short"
            "ushort", "unsigned short" -> "ushort"
            "int" -> "int"
            "uint", "unsigned int", "unsigned" -> "uint"
            "long" -> "long"
            "ulong", "unsigned long" -> "ulong"
            "longlong", "long long" -> "longlong"
            "ulonglong", "unsigned long long" -> "ulonglong"
            "float" -> "float"
            "double" -> "double"
            "void" -> return ghidra.program.model.data.VoidDataType.dataType
            "size_t" -> "size_t"       // may exist in some programs
            "ssize_t" -> "ssize_t"
            "bool" -> "bool"
            "_bool", "_bool" -> "bool"
            "int8", "int8_t" -> "int8"
            "uint8", "uint8_t" -> "uint8"
            "int16", "int16_t" -> "int16"
            "uint16", "uint16_t" -> "uint16"
            "int32", "int32_t" -> "int32"
            "uint32", "uint32_t" -> "uint32"
            "int64", "int64_t" -> "int64"
            "uint64", "uint64_t" -> "uint64"
            else -> null
        }

        if (alias != null && alias != name.lowercase()) {
            dtm.getDataType(CategoryPath.ROOT, alias)?.let { return it }
            searchCategory(dtm.rootCategory, alias)?.let { return it }
        }

        // Try with C stdint names that Ghidra uses (e.g. "int8" not "int8_t")
        if (name.endsWith("_t")) {
            val withoutT = name.dropLast(2)  // "uint8_t" -> "uint8"
            dtm.getDataType(CategoryPath.ROOT, withoutT)?.let { return it }
            searchCategory(dtm.rootCategory, withoutT)?.let { return it }
        }

        return null
    }

    private fun searchCategory(
        cat: ghidra.program.model.data.Category,
        name: String
    ): DataType? {
        for (dt in cat.dataTypes) {
            if (dt.name == name) return dt
        }
        for (subCat in cat.categories) {
            searchCategory(subCat, name)?.let { return it }
        }
        return null
    }

    // ── Function resolution ───────────────────────────────────────────────

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
