// @name: list_functions
// @author: Akiba
// @description: List functions in the binary with their entry addresses and sizes. Supports optional address range filtering.
// @parameters: startAddress (string, optional) - Start of address range (hex, e.g. "0x401000"); endAddress (string, optional) - End of address range (hex, inclusive, e.g. "0x40a000"). When both omitted, lists all functions. Each bound is independent — specify only one to list from that point onward or up to that point.

import org.iotsplab.akiba.script.AkibaScript

class ListFunctions : AkibaScript() {
    override suspend fun execute() {
        val program = currentProgram!!
        val fm = program.functionManager
        val addrFactory = program.addressFactory

        // Parse optional range — each bound is independent.
        // Explicit cast to String is required because scriptArgs values are typed Any?,
        // and the .kts compiler does not propagate smart-casts through ?.let.
        val startAddr = (scriptArgs["startAddress"] as? String)?.let { parseAddr(it, addrFactory) ?: return }
        val endAddr = (scriptArgs["endAddress"] as? String)?.let { parseAddr(it, addrFactory) ?: return }

        if (startAddr != null && endAddr != null && endAddr < startAddr) {
            appendLine("Error: endAddress < startAddress"); return
        }

        val iter = fm.getFunctions(true)
        var count = 0
        while (iter.hasNext()) {
            val func = iter.next()
            val entry = func.entryPoint

            // Skip functions outside the requested range (each bound optional)
            if (startAddr != null && entry < startAddr) {
                val body = func.body
                if (body.maxAddress < startAddr) continue
            }
            if (endAddr != null && entry > endAddr) {
                val body = func.body
                if (body.minAddress > endAddr) continue
            }

            val body = func.body
            val size = try {
                val min = body.minAddress
                val max = body.maxAddress
                if (min != null && max != null) {
                    max.subtract(min) + 1
                } else {
                    body.numAddresses
                }
            } catch (_: Exception) {
                body.numAddresses
            }

            appendLine("${func.name} @ ${func.entryPoint} (size: $size bytes)")
            count++
        }
        appendLine("\nTotal: $count functions")
    }

    private fun parseAddr(s: String, af: ghidra.program.model.address.AddressFactory): ghidra.program.model.address.Address? {
        val hex = s.trim().removePrefix("0x").removePrefix("0X")
        try {
            val v = java.lang.Long.parseLong(hex, 16)
            val addr = af.getDefaultAddressSpace().getAddress(v)
            if (addr == null) { appendLine("Error: invalid address: $s"); return null }
            return addr
        } catch (e: NumberFormatException) {
            appendLine("Error: invalid hex address: $s")
            return null
        }
    }
}
