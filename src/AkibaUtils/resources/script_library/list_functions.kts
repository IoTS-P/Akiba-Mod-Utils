// @name: list_functions
// @author: Akiba
// @description: List all functions in the binary with their entry addresses and sizes
// @parameters: none

import org.iotsplab.akiba.script.AkibaScript

class ListFunctions : AkibaScript() {
    override suspend fun execute() {
        val fm = currentProgram!!.functionManager
        val iter = fm.getFunctions(true)
        var count = 0
        while (iter.hasNext()) {
            val func = iter.next()
            val body = func.body

            // numAddresses returns 1 for not-yet-analyzed functions whose body
            // contains only the entry point. Compute size from the address range
            // span instead, which reflects what Ghidra knows about the function's
            // extent. Falls back to numAddresses if the range computation fails
            // (e.g. body spans multiple disjoint memory regions).
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
}
