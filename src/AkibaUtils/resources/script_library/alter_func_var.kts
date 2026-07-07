// @name: alter_func_var
// @author: Akiba
// @description: Alter a function's local variable: change its data type or rename it. Local variables are recovered by the Ghidra decompiler; they cannot be removed via this script (use alter_func_signature for parameter/return-type changes, or remove the whole function if needed). Locate a local by name (e.g. "local_4", "iVar1") or by stack offset (e.g. "-0x4"). Supports batch via the `operations` JSON array for renaming/retyping several locals at once.
// @parameters: target (string) - Function name or hex address (e.g. "main" or "0x401000"); name (string) - Current local variable name (e.g. "local_4", "iVar1") or stack offset (e.g. "-0x4"); action (string, default "set_type") - One of "set_type" / "rename"; type (string, for action=set_type) - Target data type name (e.g. "int", "char*", "DWORD", or a user-defined struct name); newName (string, for action=rename) - New local variable name (must be a valid identifier); operations (string, optional) - JSON array of operation objects for batch: [{"name":"local_4","action":"set_type","type":"int"},{"name":"iVar1","action":"rename","newName":"i"}]. Per-element fields: name, action, optional type, newName.
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.data.*
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Variable
import ghidra.program.model.symbol.SourceType

class AlterFuncVar : AkibaScript() {
    override suspend fun execute() {
        val program = currentProgram ?: run { appendLine("Error: no program loaded"); return }

        val target = scriptArgs["target"] as? String
            ?: run { appendLine("Error: 'target' parameter required (function name or hex address)"); return }

        val func = resolveFunction(program, target)
        if (func == null) { appendLine("Error: function '$target' not found"); return }

        val rawOps = (scriptArgs["operations"] as? String)?.takeIf { it.isNotBlank() }
        val ops: List<Map<String, Any?>> = if (rawOps != null) {
            try {
                com.fasterxml.jackson.databind.ObjectMapper().readValue(rawOps, List::class.java)
                    .map { (it as? Map<String, Any?>) ?: emptyMap() }
            } catch (e: Exception) {
                appendLine("Error: 'operations' is not a valid JSON array: ${e.message}"); return
            }
        } else {
            val name = scriptArgs["name"] as? String
                ?: run { appendLine("Error: either 'name' (single mode) or 'operations' (batch) is required"); return }
            val action = (scriptArgs["action"] as? String)?.lowercase() ?: "set_type"
            val type = scriptArgs["type"] as? String
            val newName = scriptArgs["newName"] as? String
            listOf(mapOf(
                "name" to name,
                "action" to action,
                "type" to type,
                "newName" to newName,
            ))
        }

        if (ops.isEmpty()) { appendLine("Error: 'operations' array is empty"); return }

        val txId = program.startTransaction("alter_func_var (${ops.size} op(s))")
        var committed = false
        var okCount = 0
        val failures = mutableListOf<String>()
        try {
            for ((idx, op) in ops.withIndex()) {
                val name = op["name"] as? String
                if (name.isNullOrBlank()) {
                    failures.add("[#$idx] missing 'name'"); continue
                }
                val action = (op["action"] as? String)?.lowercase() ?: "set_type"
                val typeName = op["type"] as? String
                val newName = op["newName"] as? String

                val variable = resolveLocal(func, name)
                if (variable == null) {
                    failures.add("[#$idx] '${func.name}': no local named/offset '$name'")
                    continue
                }

                when (action) {
                    "set_type" -> {
                        if (typeName.isNullOrBlank()) {
                            failures.add("[#$idx] action=set_type requires 'type'"); continue
                        }
                        val dt = resolveDataType(program.dataTypeManager, typeName)
                        if (dt == null) {
                            failures.add("[#$idx] data type '$typeName' not found"); continue
                        }
                        val old = variable.dataType.name
                        try {
                            variable.setDataType(dt, SourceType.USER_DEFINED)
                            appendLine("[#$idx] set_type: ${variable.name}: $old -> ${dt.name}  (local @ ${func.entryPoint})")
                            okCount++
                        } catch (e: Exception) {
                            failures.add("[#$idx] set_type failed on ${variable.name}: ${e.message}")
                        }
                    }
                    "rename" -> {
                        if (newName.isNullOrBlank()) {
                            failures.add("[#$idx] action=rename requires 'newName'"); continue
                        }
                        val old = variable.name
                        try {
                            variable.setName(newName, SourceType.USER_DEFINED)
                            appendLine("[#$idx] rename: $old -> $newName  (local @ ${func.entryPoint})")
                            okCount++
                        } catch (e: Exception) {
                            failures.add("[#$idx] rename failed on $old: ${e.message}")
                        }
                    }
                    else -> {
                        failures.add("[#$idx] unknown action '$action' (expected set_type / rename — local variables cannot be deleted; use alter_func_signature for parameter changes)")
                    }
                }
            }
            committed = failures.isEmpty()
            appendLine("")
            appendLine("Summary: ${ops.size} op(s), $okCount applied, ${failures.size} failed")
            if (failures.isNotEmpty()) {
                appendLine("Failures:")
                failures.forEach { appendLine("  - $it") }
            }
            appendLine("Signature: ${func.getPrototypeString(true, false)}")
        } catch (e: Exception) {
            appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, committed)
        }
    }

    /**
     * Resolves a local variable by name or stack offset.
     * Local variables are anonymous until renamed, addressed by stack offset.
     * Parameters are NOT searched — use alter_func_signature for parameter edits.
     */
    private fun resolveLocal(func: Function, name: String): Variable? {
        // Stack-offset form: e.g. "-0x4" — local only.
        if (name.startsWith("0x") || name.startsWith("-0x") ||
            (name.startsWith("0x").not() && name.startsWith("-"))) {
            val off = parseStackOffset(name) ?: return null
            for (v in func.localVariables) {
                if (v.isStackVariable && v.stackOffset == off) return v
            }
            return null
        }
        // Search by name (locals only).
        for (v in func.localVariables) {
            if (v.name.equals(name, ignoreCase = true)) return v
        }
        return null
    }

    private fun parseStackOffset(s: String): Int? {
        val cleaned = s.trim().removePrefix("0x").removePrefix("-0x")
        return try {
            val raw = if (s.startsWith("-")) "-$cleaned" else cleaned
            java.lang.Integer.parseInt(raw, 16)
        } catch (_: Exception) { null }
    }

    private fun resolveFunction(program: ghidra.program.model.listing.Program, target: String): Function? {
        val fm = program.functionManager
        val iter = fm.getFunctions(true)
        while (iter.hasNext()) { val f = iter.next(); if (f.name.equals(target, true)) return f }
        return try { val a = program.addressFactory.getAddress(target); fm.getFunctionAt(a) ?: fm.getFunctionContaining(a) }
        catch (_: Exception) { null }
    }

    private fun resolveDataType(dtm: DataTypeManager, name: String): DataType? {
        return dtm.getDataType(CategoryPath.ROOT, name)
    }
}
