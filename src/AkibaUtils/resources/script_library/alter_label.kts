// @name: alter_label
// @author: Akiba
// @description: Alter a label (global symbol) at a given address: rename it, retype the data/code unit underneath it, or delete the label. action=set_data_type applies a data type at the label's address (so naming a buffer `packet_buf` and then typing it `uint8_t[256]` is two calls). action=delete removes the user-defined label only — function entry symbols, parameter/local symbols, and default Ghidra labels are never touched.
// @parameters: target (string) - Current label name OR hex address (e.g. "main" or "0x402000"); action (string, default "rename") - One of "rename" / "set_data_type" / "delete"; newName (string, for action=rename) - New label name (must be a valid Ghidra identifier); type (string, for action=set_data_type) - Data type name to apply at the label's address (e.g. "int", "DWORD", "char", or a user-defined struct); length (integer, optional, for action=set_data_type) - Override byte length for dynamic-length types (default: type's natural length); address (string, optional) - Explicit hex address when `target` is a name that resolves ambiguously
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.data.*
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.data.DataUtilities.ClearDataMode
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolType

class AlterLabel : AkibaScript() {
    override suspend fun execute() {
        val program = currentProgram ?: run { appendLine("Error: no program loaded"); return }
        val target = scriptArgs["target"] as? String
            ?: run { appendLine("Error: 'target' parameter required (label name or hex address)"); return }
        val action = (scriptArgs["action"] as? String)?.lowercase() ?: "rename"
        val newName = scriptArgs["newName"] as? String
        val typeName = scriptArgs["type"] as? String
        val length = (scriptArgs["length"] as? Number)?.toInt() ?: -1
        val addrStr = scriptArgs["address"] as? String

        val symbolTable = program.symbolTable
        val symbols = mutableListOf<Symbol>()

        val addr = if (!addrStr.isNullOrBlank()) {
            try { program.addressFactory.getAddress(addrStr) } catch (_: Exception) { null }
        } else {
            try { program.addressFactory.getAddress(target) } catch (_: Exception) { null }
        }

        if (addr != null) {
            for (s in symbolTable.getSymbols(addr)) symbols.add(s)
        } else {
            for (s in symbolTable.getSymbols(target, null)) symbols.add(s)
        }

        if (symbols.isEmpty()) {
            appendLine("Error: no symbol found for '$target'" + if (addrStr != null) " at '$addrStr'" else "")
            return
        }

        val txId = program.startTransaction("alter_label ($action)")
        var committed = false
        try {
            var okCount = 0
            val failures = mutableListOf<String>()
            when (action) {
                "rename" -> {
                    if (newName.isNullOrBlank()) {
                        appendLine("Error: action=rename requires 'newName'")
                        return
                    }
                    // Rename the FIRST user-defined LABEL only — we don't
                    // rename function entries, parameter symbols, etc.
                    val target_sym = pickUserLabel(symbols)
                    if (target_sym == null) {
                        appendLine("Error: no user-defined LABEL found at '$target'" +
                            " (got: ${symbols.joinToString(", ") { "${it.symbolType}:${it.name}" }})")
                        return
                    }
                    val old = target_sym.name
                    target_sym.setName(newName, SourceType.USER_DEFINED)
                    appendLine("Renamed label '$old' -> '$newName' @ ${target_sym.address}")
                    okCount++
                }
                "set_data_type" -> {
                    if (typeName.isNullOrBlank()) {
                        appendLine("Error: action=set_data_type requires 'type'")
                        return
                    }
                    val dtm = program.dataTypeManager
                    val dt = resolveDataType(dtm, typeName)
                    if (dt == null) { appendLine("Error: data type '$typeName' not found"); return }
                    // set_data_type is meaningful at every label site — apply
                    // to all LABEL-type symbols at the resolved address so a
                    // multi-label address (e.g. one user + one plate) stays
                    // consistent.
                    val sites = pickAllLabelAddresses(symbols)
                    if (sites.isEmpty()) {
                        appendLine("Error: no LABEL symbol at '$target' to attach a data type to")
                        return
                    }
                    val len = if (length > 0) length else dt.length
                    val effectiveLen = if (len > 0) len else 1
                    for (sym in sites) {
                        try {
                            val data = DataUtilities.createData(
                                program, sym.address, dt, effectiveLen,
                                ClearDataMode.CLEAR_ALL_CONFLICT_DATA
                            )
                            appendLine("Defined ${dt.name} (${effectiveLen} bytes) at ${sym.address} (label '${sym.name}') -> ${data.defaultValueRepresentation}")
                            okCount++
                        } catch (e: Exception) {
                            failures.add("${sym.address} (${sym.name}): ${e.message}")
                        }
                    }
                    if (okCount == 0) {
                        appendLine("Error: set_data_type failed at every candidate site:")
                        failures.forEach { appendLine("  - $it") }
                        return
                    }
                }
                "delete" -> {
                    // Only delete user-defined LABEL symbols — protect
                    // function entries, parameter / local-variable symbols,
                    // default symbols, and external symbols from removal.
                    val deletable = symbols.filter { isDeletableUserLabel(it) }
                    if (deletable.isEmpty()) {
                        appendLine("Error: no user-defined LABEL at '$target' to delete " +
                            "(got: ${symbols.joinToString(", ") { "${it.symbolType}:${it.name}(${it.source})" }})")
                        return
                    }
                    for (sym in deletable) {
                        try {
                            val nm = sym.name
                            val sa = sym.address
                            sym.delete()
                            appendLine("Deleted label '$nm' @ $sa")
                            okCount++
                        } catch (e: Exception) {
                            failures.add("${sym.name}: ${e.message}")
                        }
                    }
                    if (okCount == 0) {
                        appendLine("Error: delete failed for every candidate label:")
                        failures.forEach { appendLine("  - $it") }
                        return
                    }
                }
                else -> {
                    appendLine("Error: unknown action '$action' (expected rename / set_data_type / delete)")
                    return
                }
            }
            committed = true
        } catch (e: Exception) {
            appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, committed)
        }
    }

    /**
     * Picks a single user-defined LABEL symbol from the resolved set.
     * Renames are inherently single-target — picking "the first user-defined
     * label" matches the documented single-symbol behaviour of the old
     * rename_label script.
     */
    private fun pickUserLabel(symbols: List<Symbol>): Symbol? =
        symbols.firstOrNull { isDeletableUserLabel(it) }

    /**
     * Returns the set of (address, symbol) pairs whose address should receive
     * a data type. Deduped by address because multiple labels can share one
     * address (primary label + plate comments, etc.).
     */
    private fun pickAllLabelAddresses(symbols: List<Symbol>): List<Symbol> =
        symbols.filter { it.symbolType == SymbolType.LABEL }
            .distinctBy { it.address }

    /**
     * A label is safe to delete / rename only when ALL of:
     *  - it's a plain LABEL (not FUNCTION / PARAMETER / LOCAL_VAR / CLASS / ...),
     *  - it's user-defined (SourceType.USER_DEFINED), not DEFAULT/IMPORT/ANALYSIS,
     *  - it's not external (an external symbol's delete throws).
     * This protects function entries, default-thunk labels, and library names
     * from accidental removal.
     */
    private fun isDeletableUserLabel(s: Symbol): Boolean =
        s.symbolType == SymbolType.LABEL &&
            s.source == SourceType.USER_DEFINED &&
            !s.isExternal

    private fun resolveDataType(dtm: DataTypeManager, name: String): DataType? {
        return dtm.getDataType(CategoryPath.ROOT, name)
    }
}