// @name: decompile_function
// @author: Akiba
// @description: Decompile a function by name or address and return the C pseudocode
// @parameters: target (string) - Function name or hex address (e.g. "main" or "0x401000"); timeout (integer, optional) - Decompilation timeout in seconds (default 120, max 600). Increase for very large functions.

import org.iotsplab.akiba.script.AkibaScript
import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileOptions
import ghidra.program.model.listing.Function
import org.iotsplab.akiba.utils.highFunction.getCCode

class DecompileFunction : AkibaScript() {
    override suspend fun execute() {
        val target = scriptArgs["target"] as? String
            ?: run { appendLine("Error: 'target' parameter is required"); return }

        val timeout = ((scriptArgs["timeout"] as? Number)?.toInt() ?: 120).coerceIn(10, 600)

        val fm = program!!.functionManager

        // Try to find by name first — iterate the FunctionIterator manually to avoid
        // Iterable/Iterator ambiguity when calling .asSequence().
        var func: Function? = null
        val iter = fm.getFunctions(true)
        while (iter.hasNext()) {
            val f = iter.next()
            if (f.name.equals(target, ignoreCase = true)) {
                func = f
                break
            }
        }

        if (func == null) {
            // Try as address
            val addr = try {
                program!!.addressFactory.getAddress(target)
            } catch (_: Exception) { null }
            if (addr != null) {
                func = fm.getFunctionAt(addr) ?: fm.getFunctionContaining(addr)
            }
        }

        if (func == null) {
            appendLine("Error: Function '$target' not found")
            return
        }

        appendLine("// Function: ${func.name} @ ${func.entryPoint}")
        appendLine("// Size: ${func.body.numAddresses} bytes")
        appendLine("")
        try {
            appendLine(func.getCCode(timeout))
        } catch (e: Exception) {
            appendLine("// Decompilation failed: ${e.message}")
            if (e is IllegalStateException && e.message?.contains("within") == true) {
                appendLine("// This is likely a TIMEOUT. Re-run with a larger 'timeout' parameter (e.g. 300 or 600).")
            }
        }
    }
}
