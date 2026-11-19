// @name: decompile_function
// @author: Akiba
// @description: Decompile a function by name or address and return the C pseudocode
// @parameters: target (string) - Function name or hex address (e.g. "main" or "0x401000"); timeout (integer, optional) - Decompilation timeout in seconds (default 120, max 600). Increase for very large functions.

import org.iotsplab.akiba.script.AkibaScript
import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileOptions
import ghidra.program.model.listing.Function

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
        val iface = DecompInterface()
        try {
            iface.setOptions(DecompileOptions())
            if (!iface.openProgram(program)) {
                appendLine("// Decompilation failed: the decompiler refused to open the program")
                return
            }
            val results = iface.decompileFunction(func, timeout, taskGlobalMonitor)
            if (results == null || !results.decompileCompleted()) {
                val why = results?.errorMessage ?: "no result"
                appendLine("// Decompilation failed: $why")
                appendLine("// If this looks like a timeout, re-run with a larger 'timeout' parameter (e.g. 300 or 600).")
                return
            }
            appendLine(results.decompiledFunction?.c ?: "// Decompilation produced no text")
        } catch (e: Exception) {
            appendLine("// Decompilation failed: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            iface.dispose()
        }
    }
}
