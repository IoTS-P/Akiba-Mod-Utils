// @name: find_data_type_refs
// @author: Akiba
// @description: Find all functions whose parameters (or local variables) use a given data type, and all defined data instances of that type. By default only scans function PARAMETERS (fast — no decompilation needed). Set includeLocals=true to also scan local variables (requires decompilation of each function, so it is much slower). Set includeData=true to also list all defined data items (globals, statics) whose data type matches. The data type is matched by name (case-insensitive exact match) — use action=search on manage_data_type to find the exact type name first.
// @parameters: name (string, required) - Data type name to search for (case-insensitive, exact match, e.g. "ParseCtx" or "yaml_emitter_t"); includeLocals (boolean, optional, default false) - Also scan local variables (requires decompilation — slow for large binaries); includeData (boolean, optional, default false) - Also list defined data items (globals/statics) with this type; limit (int, optional, default 200) - Maximum number of function results to return; dataLimit (int, optional, default 100) - Maximum number of defined-data results to return
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Variable

class FindDataTypeRefs : AkibaScript() {

    override suspend fun execute() {
        val program = this.program ?: run { appendLine("Error: no program loaded"); return }
        val typeName = scriptArgs["name"] as? String
            ?: run { appendLine("Error: 'name' parameter is required"); return }
        val includeLocals = (scriptArgs["includeLocals"] as? Boolean) ?: false
        val includeData = (scriptArgs["includeData"] as? Boolean) ?: false
        val limit = ((scriptArgs["limit"] as? Number)?.toInt() ?: 200).coerceIn(1, 1000)
        val dataLimit = ((scriptArgs["dataLimit"] as? Number)?.toInt() ?: 100).coerceIn(1, 500)

        val dtm = program.dataTypeManager

        // ── Resolve the target data type by name ──────────────────────────
        // Match by case-insensitive name against all types in the DTM.
        val targetDt = findDataTypeByName(dtm, typeName)
        if (targetDt == null) {
            appendLine("Error: data type '$typeName' not found in the program's data type manager.")
            appendLine("  Use manage_data_type action=search to find available types.")
            return
        }

        appendLine("=== Find Data Type References ===")
        appendLine("Type: ${targetDt.name} (${targetDt.javaClass.simpleName}, ${targetDt.length} bytes)")
        appendLine("Category: ${targetDt.categoryPath.path}")
        appendLine("Scan parameters: yes")
        appendLine("Scan locals: ${if (includeLocals) "yes (requires decompilation — may be slow)" else "no"}")
        appendLine("Scan defined data: ${if (includeData) "yes" else "no"}")
        appendLine("")

        val targetNameLower = targetDt.name.lowercase()

        // ── Helper: check if a variable's data type matches ───────────────
        // Match if the variable's type name equals the target name,
        // OR the variable's type is a pointer/array whose base type matches.
        fun typeMatches(dt: DataType): Boolean {
            // Direct name match (case-insensitive)
            if (dt.name.lowercase() == targetNameLower) return true
            // Pointer: check the pointed-to type
            if (dt is ghidra.program.model.data.Pointer) {
                val base = dt.dataType
                if (base != null && base.name.lowercase() == targetNameLower) return true
            }
            // Array: check the element type
            if (dt is ghidra.program.model.data.Array) {
                val elem = dt.dataType
                if (elem != null && elem.name.lowercase() == targetNameLower) return true
                // Pointer-to-array of target
                if (elem is ghidra.program.model.data.Pointer) {
                    val base = elem.dataType
                    if (base != null && base.name.lowercase() == targetNameLower) return true
                }
            }
            // Typedef: check the underlying type
            if (dt is ghidra.program.model.data.TypeDef) {
                return typeMatches(dt.dataType)
            }
            return false
        }

        // ── 1. Scan functions for matching parameters (and optionally locals) ──
        val fm = program.functionManager
        val paramMatches = mutableListOf<ParamMatch>()
        val localMatches = mutableListOf<LocalMatch>()

        val funcIter = fm.getFunctions(true)
        while (funcIter.hasNext()) {
            val func = funcIter.next()

            // Skip external/thunk functions
            if (func.isExternal || func.isThunk) continue

            // Check parameters (fast — no decompilation)
            val matchedParams = mutableListOf<MatchedVar>()
            for (param in func.parameters) {
                if (typeMatches(param.dataType)) {
                    matchedParams.add(MatchedVar(param.name, param.dataType.name, param.ordinal))
                }
            }
            if (matchedParams.isNotEmpty()) {
                paramMatches.add(ParamMatch(func, matchedParams))
            }

            // Check return type
            if (typeMatches(func.returnType)) {
                paramMatches.add(ParamMatch(func, listOf(
                    MatchedVar("<return>", func.returnType.name, -1)
                )))
            }

            // Check locals (slow — triggers decompilation)
            if (includeLocals) {
                try {
                    val locals = func.localVariables
                    val matchedLocals = mutableListOf<MatchedVar>()
                    for (local in locals) {
                        if (typeMatches(local.dataType)) {
                            matchedLocals.add(MatchedVar(local.name, local.dataType.name, local.ordinal))
                        }
                    }
                    if (matchedLocals.isNotEmpty()) {
                        localMatches.add(LocalMatch(func, matchedLocals))
                    }
                } catch (_: Exception) {
                    // Decompilation may fail for some functions — skip silently
                }
            }
        }

        // ── Report parameter matches ──────────────────────────────────────
        appendLine("--- Functions with matching parameters (${paramMatches.size}) ---")
        if (paramMatches.isEmpty()) {
            appendLine("  (none)")
        } else {
            val shown = paramMatches.take(limit)
            for (m in shown) {
                val varList = m.vars.joinToString(", ") { v ->
                    if (v.ordinal >= 0) "param[${v.ordinal}] ${v.name}: ${v.typeName}"
                    else "${v.name}: ${v.typeName}"
                }
                appendLine("  • ${m.func.name} @ ${m.func.entryPoint}  ($varList)")
            }
            if (paramMatches.size > limit) {
                appendLine("  ... (+${paramMatches.size - limit} more, increase 'limit' to see all)")
            }
        }

        // ── Report local variable matches (if requested) ──────────────────
        if (includeLocals) {
            appendLine("")
            appendLine("--- Functions with matching locals (${localMatches.size}) ---")
            if (localMatches.isEmpty()) {
                appendLine("  (none)")
            } else {
                val shown = localMatches.take(limit)
                for (m in shown) {
                    val varList = m.vars.joinToString(", ") { v ->
                        "${v.name}: ${v.typeName}"
                    }
                    appendLine("  • ${m.func.name} @ ${m.func.entryPoint}  ($varList)")
                }
                if (localMatches.size > limit) {
                    appendLine("  ... (+${localMatches.size - limit} more)")
                }
            }
        }

        // ── 2. Scan defined data items (if requested) ─────────────────────
        var dataMatchCount = 0
        if (includeData) {
            val dataMatches = mutableListOf<DataMatch>()
            val dataIter = program.listing.getDefinedData(true)
            while (dataIter.hasNext()) {
                val data = dataIter.next()
                if (typeMatches(data.dataType)) {
                    val containingFunc = fm.getFunctionContaining(data.minAddress)
                    dataMatches.add(DataMatch(
                        data.minAddress,
                        data.dataType.name,
                        data.length,
                        containingFunc?.name
                    ))
                }
            }
            dataMatchCount = dataMatches.size

            appendLine("")
            appendLine("--- Defined data items (${dataMatches.size}) ---")
            if (dataMatches.isEmpty()) {
                appendLine("  (none)")
            } else {
                val shown = dataMatches.take(dataLimit)
                for (m in shown) {
                    val ctx = if (m.containingFunc != null) " [in ${m.containingFunc}]" else ""
                    appendLine("  • ${m.address}  ${m.typeName} (${m.length} bytes)$ctx")
                }
                if (dataMatches.size > dataLimit) {
                    appendLine("  ... (+${dataMatches.size - dataLimit} more, increase 'dataLimit' to see all)")
                }
            }
        }

        // ── Summary ───────────────────────────────────────────────────────
        appendLine("")
        appendLine("Summary: ${paramMatches.size} function(s) with matching parameters" +
            (if (includeLocals) ", ${localMatches.size} with matching locals" else "") +
            (if (includeData) ", $dataMatchCount data item(s)" else ""))
    }

    // ── Data classes ──────────────────────────────────────────────────────

    private data class MatchedVar(val name: String, val typeName: String, val ordinal: Int)
    private data class ParamMatch(val func: Function, val vars: List<MatchedVar>)
    private data class LocalMatch(val func: Function, val vars: List<MatchedVar>)
    private data class DataMatch(
        val address: ghidra.program.model.address.Address,
        val typeName: String,
        val length: Int,
        val containingFunc: String?
    )

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun findDataTypeByName(
        dtm: ghidra.program.model.data.DataTypeManager,
        name: String
    ): DataType? {
        val nameLower = name.lowercase()
        val iter = dtm.allDataTypes
        while (iter.hasNext()) {
            val dt = iter.next()
            if (dt.name.lowercase() == nameLower) return dt
        }
        return null
    }
}
