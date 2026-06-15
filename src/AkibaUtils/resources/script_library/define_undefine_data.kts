// @name: define_undefine_data
// @author: Akiba
// @description: Define or undefine data at a given address. To define: provide an address and a data type name. To undefine: set action to "clear". Optionally specify length for dynamic data types.
// @parameters: address (string) - Hex address in the program; action (string, optional) - "define" or "clear" (default: "define"); type (string, optional) - Data type name, e.g. "int", "DWORD", "PointerType", "undefined" (required for action=define); length (integer, optional) - Override length for dynamic types (default: auto from data type)

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.data.*
import ghidra.program.model.listing.Data
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.data.DataUtilities.ClearDataMode

class DefineUndefineData : AkibaScript() {
    override suspend fun execute() {
        val program = currentProgram ?: run { appendLine("Error: no program loaded"); return }
        val addressStr = scriptArgs["address"] as? String
            ?: run { appendLine("Error: 'address' parameter required"); return }
        val action = (scriptArgs["action"] as? String)?.lowercase() ?: "define"

        val address = try { program.addressFactory.getAddress(addressStr) }
            catch (_: Exception) { null }
        if (address == null) { appendLine("Error: invalid address '$addressStr'"); return }

        val txId = program.startTransaction("define_undefine_data")
        var ok = false
        try {
            when (action) {
                "define" -> doDefine(program, address)
                "clear" -> doClear(program, address)
                else -> { appendLine("Error: action must be 'define' or 'clear'"); return }
            }
            ok = true
        } catch (e: Exception) {
            appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, ok)
        }
    }

    private fun doDefine(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) {
        val typeName = scriptArgs["type"] as? String
            ?: run { appendLine("Error: 'type' parameter required for define action"); return }
        val dtm = program.dataTypeManager
        val dataType = resolveDataType(dtm, typeName)
        if (dataType == null) { appendLine("Error: data type '$typeName' not found"); return }

        val length = (scriptArgs["length"] as? Number)?.toInt() ?: -1
        val actualLen = if (length > 0) length else dataType.length
        val len = if (actualLen > 0) actualLen else 1

        try {
            val data = DataUtilities.createData(program, address, dataType, len,
                ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
            appendLine("Defined ${dataType.name} at $address (${len} bytes)")
            appendLine("Result: ${data.defaultValueRepresentation}")
        } catch (e: Exception) {
            appendLine("Error creating data at $address: ${e.message}")
        }
    }

    private fun doClear(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) {
        val listing = program.listing
        val existing = listing.getDefinedDataAt(address)
        if (existing == null) {
            appendLine("Nothing defined at $address — already clear")
            return
        }
        val oldType = existing.dataType.name
        val size = existing.length.toLong()
        listing.clearCodeUnits(address, address.add(size - 1), true)
        appendLine("Cleared $oldType ($size bytes) at $address")
    }

    private fun resolveDataType(dtm: DataTypeManager, name: String): DataType? {
        return dtm.getDataType(CategoryPath.ROOT, name)
    }
}
