// @name: alter_func_signature
// @author: Akiba
// @description: Modify a function's signature: rename the function, change its return type, set calling convention / varargs / no-return / inline flags, or modify its parameters (set type, rename, add, remove). Per-parameter type and name are set on the existing Parameter object; add/remove rebuild the parameter list via the recommended `replaceParameters` API. Use alter_func_var to retype/rename local variables inside a function body. For complex multi-param refactors, prefer batch `operations` mode to keep edits atomic in a single transaction.
// @parameters: target (string) - Function name or hex address (e.g. "main" or "0x401000"); action (string, default "set_return_type") - One of "rename" / "set_return_type" / "set_calling_convention" / "set_varargs" / "set_no_return" / "set_inline" / "set_param_type" / "rename_param" / "add_param" / "remove_param"; newName (string, for action=rename) - New function name; returnType (string, for action=set_return_type) - Return type name (e.g. "int", "bool", "void"); callingConvention (string, for action=set_calling_convention) - Calling convention name known to the program's compiler spec (e.g. "cdecl", "stdcall", "fastcall", "__thiscall", "default"); varArgs (string, for action=set_varargs) - "true" or "false"; noReturn (string, for action=set_no_return) - "true" or "false"; inline (string, for action=set_inline) - "true" or "false"; paramOrdinal (integer, optional) - 0-based index of the target parameter in the signature (auto-params included — use paramName to disambiguate); paramName (string, optional) - Current parameter name (case-insensitive, alternative to paramOrdinal); paramType (string, for action=set_param_type / add_param) - Target parameter type name (e.g. "int", "char*", "size_t"); newParamName (string, for action=rename_param) - New parameter name; addName (string, for action=add_param, optional) - Name for the added parameter (default = auto-generated, e.g. "param_N"); addPosition (integer, for action=add_param, optional) - 0-based insert position in the user-visible parameter list (default = append at the end); operations (string, optional) - JSON array of operation objects for batch: [{"action":"set_param_type","paramOrdinal":0,"paramType":"int"},{"action":"rename_param","paramName":"param_2","newParamName":"buf"},{"action":"add_param","name":"len","type":"size_t","position":2},{"action":"remove_param","paramOrdinal":3}]. Allowed per-element actions: rename / set_return_type / set_calling_convention / set_varargs / set_no_return / set_inline / set_param_type / rename_param / add_param / remove_param. Per-element fields depend on the action.

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.data.*
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Function.FunctionUpdateType
import ghidra.program.model.listing.Parameter
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.symbol.SourceType

class AlterFuncSignature : AkibaScript() {
    override suspend fun execute() {
        val program = currentProgram ?: run { appendLine("Error: no program loaded"); return }

        val target = scriptArgs["target"] as? String
            ?: run { appendLine("Error: 'target' parameter required (function name or hex address)"); return }

        val func = resolveFunction(program, target)
        if (func == null) { appendLine("Error: function '$target' not found"); return }

        val rawOps = (scriptArgs["operations"] as? String)?.takeIf { it.isNotBlank() }
        @Suppress("UNCHECKED_CAST")
        val ops: List<Map<String, Any?>> = if (rawOps != null) {
            try {
                com.fasterxml.jackson.databind.ObjectMapper().readValue(rawOps, List::class.java)
                    .map { (it as? Map<String, Any?>) ?: emptyMap() }
            } catch (e: Exception) {
                appendLine("Error: 'operations' is not a valid JSON array: ${e.message}"); return
            }
        } else {
            listOf(mapOf(
                "action" to ((scriptArgs["action"] as? String)?.lowercase() ?: "set_return_type"),
                "newName" to (scriptArgs["newName"] as? String),
                "returnType" to (scriptArgs["returnType"] as? String),
                "callingConvention" to (scriptArgs["callingConvention"] as? String),
                "varArgs" to (scriptArgs["varArgs"] as? String),
                "noReturn" to (scriptArgs["noReturn"] as? String),
                "inline" to (scriptArgs["inline"] as? String),
                "paramOrdinal" to ((scriptArgs["paramOrdinal"] as? Number)?.toInt()),
                "paramName" to (scriptArgs["paramName"] as? String),
                "paramType" to (scriptArgs["paramType"] as? String),
                "newParamName" to (scriptArgs["newParamName"] as? String),
                "name" to (scriptArgs["addName"] as? String),
                "type" to (scriptArgs["paramType"] as? String),
                "position" to ((scriptArgs["addPosition"] as? Number)?.toInt()),
            ))
        }

        if (ops.isEmpty()) { appendLine("Error: 'operations' array is empty"); return }

        val txId = program.startTransaction("alter_func_signature (${ops.size} op(s))")
        var committed = false
        var okCount = 0
        val failures = mutableListOf<String>()
        try {
            for ((idx, op) in ops.withIndex()) {
                val action = (op["action"] as? String)?.lowercase() ?: ""
                if (action.isBlank()) {
                    failures.add("[#$idx] missing 'action'"); continue
                }
                when (action) {
                    "rename" -> okCount += doRename(func, op, idx, failures)
                    "set_return_type" -> okCount += doSetReturnType(func, op, idx, program, failures)
                    "set_calling_convention" -> okCount += doSetCallingConvention(func, op, idx, failures)
                    "set_varargs" -> okCount += doSetVarArgs(func, op, idx, failures)
                    "set_no_return" -> okCount += doSetNoReturn(func, op, idx, failures)
                    "set_inline" -> okCount += doSetInline(func, op, idx, failures)
                    "set_param_type" -> okCount += doSetParamType(func, op, idx, program, failures)
                    "rename_param" -> okCount += doRenameParam(func, op, idx, failures)
                    "add_param" -> okCount += doAddParam(func, op, idx, program, failures)
                    "remove_param" -> okCount += doRemoveParam(func, op, idx, program, failures)
                    else -> failures.add("[#$idx] unknown action '$action' (expected rename / set_return_type / set_calling_convention / set_varargs / set_no_return / set_inline / set_param_type / rename_param / add_param / remove_param)")
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

    // ─── Function-level actions ────────────────────────────────────────────

    private fun doRename(func: Function, op: Map<String, Any?>, idx: Int, failures: MutableList<String>): Int {
        val newName = op["newName"] as? String
        if (newName.isNullOrBlank()) {
            failures.add("[#$idx] action=rename requires 'newName'"); return 0
        }
        val old = func.name
        return try {
            func.setName(newName, SourceType.USER_DEFINED)
            appendLine("[#$idx] rename: $old -> $newName  (function @ ${func.entryPoint})")
            1
        } catch (e: Exception) {
            failures.add("[#$idx] rename failed on '$old': ${e.message}")
            0
        }
    }

    private fun doSetReturnType(func: Function, op: Map<String, Any?>, idx: Int, program: ghidra.program.model.listing.Program, failures: MutableList<String>): Int {
        val typeName = op["returnType"] as? String
        if (typeName.isNullOrBlank()) {
            failures.add("[#$idx] action=set_return_type requires 'returnType'"); return 0
        }
        val dt = resolveDataType(program.dataTypeManager, typeName)
        if (dt == null) {
            failures.add("[#$idx] return type '$typeName' not found"); return 0
        }
        val old = func.returnType.name
        return try {
            func.setReturnType(dt, SourceType.USER_DEFINED)
            appendLine("[#$idx] set_return_type: $old -> ${dt.name}  (function @ ${func.entryPoint})")
            1
        } catch (e: Exception) {
            failures.add("[#$idx] set_return_type failed: ${e.message}")
            0
        }
    }

    private fun doSetCallingConvention(func: Function, op: Map<String, Any?>, idx: Int, failures: MutableList<String>): Int {
        val name = op["callingConvention"] as? String
        if (name.isNullOrBlank()) {
            failures.add("[#$idx] action=set_calling_convention requires 'callingConvention'"); return 0
        }
        val old = func.callingConventionName
        return try {
            func.setCallingConvention(name)
            appendLine("[#$idx] set_calling_convention: $old -> $name  (function @ ${func.entryPoint})")
            1
        } catch (e: Exception) {
            failures.add("[#$idx] set_calling_convention failed: ${e.message}")
            0
        }
    }

    private fun doSetVarArgs(func: Function, op: Map<String, Any?>, idx: Int, failures: MutableList<String>): Int {
        val v = parseBool(op["varArgs"])
        if (v == null) {
            failures.add("[#$idx] action=set_varargs requires 'varArgs' (true/false)"); return 0
        }
        val old = func.hasVarArgs()
        return try {
            func.setVarArgs(v)
            appendLine("[#$idx] set_varargs: $old -> $v  (function @ ${func.entryPoint})")
            1
        } catch (e: Exception) {
            failures.add("[#$idx] set_varargs failed: ${e.message}")
            0
        }
    }

    private fun doSetNoReturn(func: Function, op: Map<String, Any?>, idx: Int, failures: MutableList<String>): Int {
        val v = parseBool(op["noReturn"])
        if (v == null) {
            failures.add("[#$idx] action=set_no_return requires 'noReturn' (true/false)"); return 0
        }
        val old = func.hasNoReturn()
        return try {
            func.setNoReturn(v)
            appendLine("[#$idx] set_no_return: $old -> $v  (function @ ${func.entryPoint})")
            1
        } catch (e: Exception) {
            failures.add("[#$idx] set_no_return failed: ${e.message}")
            0
        }
    }

    private fun doSetInline(func: Function, op: Map<String, Any?>, idx: Int, failures: MutableList<String>): Int {
        val v = parseBool(op["inline"])
        if (v == null) {
            failures.add("[#$idx] action=set_inline requires 'inline' (true/false)"); return 0
        }
        val old = func.isInline
        return try {
            func.setInline(v)
            appendLine("[#$idx] set_inline: $old -> $v  (function @ ${func.entryPoint})")
            1
        } catch (e: Exception) {
            failures.add("[#$idx] set_inline failed: ${e.message}")
            0
        }
    }

    // ─── Parameter-level actions ───────────────────────────────────────────

    private fun doSetParamType(func: Function, op: Map<String, Any?>, idx: Int, program: ghidra.program.model.listing.Program, failures: MutableList<String>): Int {
        val typeName = op["paramType"] as? String
        if (typeName.isNullOrBlank()) {
            failures.add("[#$idx] action=set_param_type requires 'paramType'"); return 0
        }
        val ordinal = (op["paramOrdinal"] as? Number)?.toInt()
        val name = op["paramName"] as? String
        val param = findParameter(func, ordinal, name, idx, failures, "set_param_type") ?: return 0
        val dt = resolveDataType(program.dataTypeManager, typeName)
        if (dt == null) {
            failures.add("[#$idx] param type '$typeName' not found"); return 0
        }
        val old = param.dataType.name
        return try {
            param.setDataType(dt, SourceType.USER_DEFINED)
            appendLine("[#$idx] set_param_type: param[${param.ordinal}] ${param.name}: $old -> ${dt.name}  (function @ ${func.entryPoint})")
            1
        } catch (e: Exception) {
            failures.add("[#$idx] set_param_type failed on ${param.name}: ${e.message}")
            0
        }
    }

    private fun doRenameParam(func: Function, op: Map<String, Any?>, idx: Int, failures: MutableList<String>): Int {
        val newName = op["newParamName"] as? String
        if (newName.isNullOrBlank()) {
            failures.add("[#$idx] action=rename_param requires 'newParamName'"); return 0
        }
        val ordinal = (op["paramOrdinal"] as? Number)?.toInt()
        val name = op["paramName"] as? String
        val param = findParameter(func, ordinal, name, idx, failures, "rename_param") ?: return 0
        val old = param.name
        return try {
            param.setName(newName, SourceType.USER_DEFINED)
            appendLine("[#$idx] rename_param: param[${param.ordinal}] $old -> $newName  (function @ ${func.entryPoint})")
            1
        } catch (e: Exception) {
            failures.add("[#$idx] rename_param failed on '$old': ${e.message}")
            0
        }
    }

    private fun doAddParam(func: Function, op: Map<String, Any?>, idx: Int, program: ghidra.program.model.listing.Program, failures: MutableList<String>): Int {
        val typeName = (op["type"] as? String) ?: (op["paramType"] as? String)
        if (typeName.isNullOrBlank()) {
            failures.add("[#$idx] action=add_param requires 'type' (or 'paramType')"); return 0
        }
        val newName = (op["name"] as? String) ?: (op["addName"] as? String)
        val position = (op["position"] as? Number)?.toInt() ?: -1
        val dt = resolveDataType(program.dataTypeManager, typeName)
        if (dt == null) {
            failures.add("[#$idx] param type '$typeName' not found"); return 0
        }
        // User-visible parameters only (auto-params such as `this` / `__return_storage_ptr__`
        // are re-injected by the calling convention / return type and must not be re-listed).
        val existing = func.getParameters().filter { !it.isAutoParameter }
        val safePos = if (position < 0) existing.size else position.coerceIn(0, existing.size)
        val newList = mutableListOf<Parameter>()
        for ((i, p) in existing.withIndex()) {
            if (i == safePos) newList.add(ParameterImpl(newName ?: "", dt, program, SourceType.USER_DEFINED))
            newList.add(ParameterImpl(p.name, p.dataType, program, SourceType.USER_DEFINED))
        }
        if (safePos >= existing.size) {
            newList.add(ParameterImpl(newName ?: "", dt, program, SourceType.USER_DEFINED))
        }
        return try {
            // DYNAMIC_STORAGE_ALL_PARAMS lets Ghidra reassign storage for the rebuilt
            // list (and the freshly-added parameter). force=true clears any local
            // whose old storage now collides with the new parameter.
            func.replaceParameters(newList, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED)
            appendLine("[#$idx] add_param: ${dt.name} at position $safePos${if (!newName.isNullOrBlank()) " '$newName'" else ""}  (function @ ${func.entryPoint})")
            appendLine("  Signature: ${func.getPrototypeString(true, false)}")
            1
        } catch (e: Exception) {
            failures.add("[#$idx] add_param failed: ${e.message}")
            0
        }
    }

    private fun doRemoveParam(func: Function, op: Map<String, Any?>, idx: Int, program: ghidra.program.model.listing.Program, failures: MutableList<String>): Int {
        val ordinal = (op["paramOrdinal"] as? Number)?.toInt()
        val name = op["paramName"] as? String
        val param = findParameter(func, ordinal, name, idx, failures, "remove_param") ?: return 0
        if (param.isAutoParameter) {
            failures.add("[#$idx] cannot remove auto-parameter '${param.name}' (inserted by calling convention); use set_calling_convention or set_return_type to change the function shape")
            return 0
        }
        val removedOrdinal = param.ordinal
        val removedName = param.name
        val existing = func.getParameters().filter { !it.isAutoParameter }
        val newList = existing
            .filter { it.ordinal != removedOrdinal }
            .map { ParameterImpl(it.name, it.dataType, program, SourceType.USER_DEFINED) }
        return try {
            func.replaceParameters(newList, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED)
            appendLine("[#$idx] remove_param: param[$removedOrdinal] '$removedName' removed  (function @ ${func.entryPoint})")
            appendLine("  Signature: ${func.getPrototypeString(true, false)}")
            1
        } catch (e: Exception) {
            failures.add("[#$idx] remove_param failed: ${e.message}")
            0
        }
    }

    // ─── Helpers ───────────────────────────────────────────────────────────

    /**
     * Locate a parameter by 0-based ordinal or by case-insensitive name.
     * Auto-parameters are searched too so the caller can retype / rename them when needed.
     */
    private fun findParameter(
        func: Function,
        ordinal: Int?,
        name: String?,
        idx: Int,
        failures: MutableList<String>,
        action: String,
    ): Parameter? {
        val params = func.getParameters().toList()
        if (ordinal != null) {
            if (ordinal < 0 || ordinal >= params.size) {
                failures.add("[#$idx] action=$action: paramOrdinal $ordinal out of range (have ${params.size} parameter(s))")
                return null
            }
            return params[ordinal]
        }
        if (!name.isNullOrBlank()) {
            for (p in params) {
                if (p.name.equals(name, ignoreCase = true)) return p
            }
            failures.add("[#$idx] action=$action: no parameter named '$name' (have ${params.size} parameter(s))")
            return null
        }
        failures.add("[#$idx] action=$action requires 'paramOrdinal' or 'paramName'")
        return null
    }

    private fun parseBool(v: Any?): Boolean? {
        return when (v) {
            is Boolean -> v
            is String -> when (v.lowercase()) {
                "true", "1", "yes", "on" -> true
                "false", "0", "no", "off" -> false
                else -> null
            }
            is Number -> v.toInt() != 0
            else -> null
        }
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
