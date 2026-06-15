// @name: rename_label
// @author: Akiba
// @description: Rename a label (global symbol) at a given address. Find the label by its current name or at a specific hex address.
// @parameters: target (string) - Current label name OR hex address (e.g. "main" or "0x402000"); newName (string) - New label name; address (string, optional) - Explicit hex address if target is a name that resolves ambiguously

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol

class RenameLabel : AkibaScript() {
    override suspend fun execute() {
        val program = currentProgram ?: run { appendLine("Error: no program loaded"); return }
        val target = scriptArgs["target"] as? String
            ?: run { appendLine("Error: 'target' parameter required"); return }
        val newName = scriptArgs["newName"] as? String
            ?: run { appendLine("Error: 'newName' parameter required"); return }
        val addrStr = scriptArgs["address"] as? String

        val symbolTable = program.symbolTable

        // Find the symbol — getSymbols returns arrays, not iterators
        val symbols = mutableListOf<Symbol>()

        val addr = if (!addrStr.isNullOrBlank()) {
            try { program.addressFactory.getAddress(addrStr) } catch (_: Exception) { null }
        } else {
            try { program.addressFactory.getAddress(target) } catch (_: Exception) { null }
        }

        if (addr != null) {
            // Search by address
            val arr = symbolTable.getSymbols(addr)
            for (s in arr) symbols.add(s)
        } else {
            // Search by name across all namespaces
            val arr = symbolTable.getSymbols(target, null)
            for (s in arr) symbols.add(s)
        }

        if (symbols.isEmpty()) {
            appendLine("Error: no symbol found for '$target'" +
                if (addrStr != null) " at '$addrStr'" else "")
            return
        }

        val symbol = symbols.first()
        val oldName = symbol.name
        val symAddr = symbol.address

        val txId = program.startTransaction("rename_label")
        var ok = false
        try {
            symbol.setName(newName, SourceType.USER_DEFINED)
            ok = true
            appendLine("Renamed label '$oldName' -> '$newName' @ $symAddr")
        } catch (e: Exception) {
            appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, ok)
        }
    }
}
