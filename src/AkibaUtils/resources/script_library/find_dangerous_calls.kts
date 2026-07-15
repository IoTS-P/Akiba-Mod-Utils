// @name: find_dangerous_calls
// @author: Akiba
// @description: Find calls to known-insecure C functions (gets, strcpy, sprintf, strcat, scanf, system, etc.) and list their callers
// @parameters: none

import org.iotsplab.akiba.script.AkibaScript

class FindDangerousCalls : AkibaScript() {
    override suspend fun execute() {
        val dangerousFns = listOf(
            "gets", "strcpy", "strncpy", "strcat", "strncat",
            "sprintf", "vsprintf", "scanf", "sscanf", "fscanf",
            "system", "popen", "exec", "execve",
            "memcpy", "memmove", "realpath"
        )

        val fm = program!!.functionManager
        val refMgr = program!!.referenceManager
        var totalFound = 0

        val iter = fm.getFunctions(true)
        while (iter.hasNext()) {
            val func = iter.next()
            if (func.name in dangerousFns) {
                val refs = refMgr.getReferencesTo(func.entryPoint)
                val callers = mutableListOf<String>()
                refs.forEach { ref ->
                    val caller = fm.getFunctionContaining(ref.fromAddress)
                    callers.add("  ${caller?.name ?: "unknown"} @ ${ref.fromAddress}")
                }
                if (callers.isNotEmpty()) {
                    appendLine("[!] ${func.name} @ ${func.entryPoint} — ${callers.size} call site(s):")
                    callers.forEach { appendLine(it) }
                    appendLine("")
                    totalFound += callers.size
                }
            }
        }

        if (totalFound == 0) {
            appendLine("No calls to known-insecure functions found.")
        } else {
            appendLine("Total: $totalFound call sites to insecure functions.")
        }
    }
}
