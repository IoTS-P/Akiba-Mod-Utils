// @name: list_functions
// @author: Akiba
// @description: List functions in the binary with their entry addresses and sizes. Supports optional address range filtering, regex name search, and annotations for non-project-owned functions (external, thunk, library, PLT stub, runtime helper) so the agent can skip them immediately.
// @parameters: startAddress (string, optional) - Start of address range (hex, e.g. "0x401000"); endAddress (string, optional) - End of address range (hex, inclusive, e.g. "0x40a000"). Each bound is independent — specify only one to list from that point onward or up to that point. search (string, optional) - Regex pattern to match function names (partial match, case-insensitive). Only functions whose name matches the pattern are listed. The alias `filter` is also accepted for backward compatibility. annotate (boolean, optional) - When true (default), appends `[note: ...]` to non-project-owned functions so the agent can skip them without a separate call.

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.listing.Function

class ListFunctions : AkibaScript() {

    companion object {
        val ELF_COMPILER_HELPERS = setOf(
            "_init", "_fini", "frame_dummy", "call_weak_fn",
            "register_tm_clones", "deregister_tm_clones", "__do_global_dtors_aux"
        )
    }

    override suspend fun execute() {
        val program = this.program!!
        val fm = program.functionManager
        val addrFactory = program.addressFactory

        // Parse optional range — each bound is independent.
        val startAddr = (scriptArgs["startAddress"] as? String)?.let { parseAddr(it, addrFactory) ?: return }
        val endAddr = (scriptArgs["endAddress"] as? String)?.let { parseAddr(it, addrFactory) ?: return }
        // Accept `search` as the primary name (matches the natural English verb
        // and the way callers pass it) and `filter` as a backward-compatible
        // alias. Without this dual lookup, callers that use the alias they
        // saw in older transcripts or documentation would silently get the
        // full list back.
        val nameFilter = ((scriptArgs["search"] as? String) ?: (scriptArgs["filter"] as? String))?.takeIf { it.isNotBlank() }
        val annotate = (scriptArgs["annotate"] as? Boolean) ?: true

        if (startAddr != null && endAddr != null && endAddr < startAddr) {
            appendLine("Error: endAddress < startAddress"); return
        }

        val iter = fm.getFunctions(true)
        var count = 0
        var filtered = 0
        while (iter.hasNext()) {
            val func = iter.next()
            val entry = func.entryPoint

            // Name filter (case-insensitive, partial match)
            if (nameFilter != null) {
                val pattern = try {
                    Regex(nameFilter, RegexOption.IGNORE_CASE)
                } catch (e: Exception) {
                    appendLine("Error: invalid regex pattern '$nameFilter': ${e.message}"); return
                }
                if (!pattern.containsMatchIn(func.name)) {
                    filtered++
                    continue
                }
            }

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

            val note = if (annotate) classifyFunction(func) else ""
            appendLine("${func.name} @ ${func.entryPoint} (size: $size bytes)$note")
            count++
        }
        if (nameFilter != null) appendLine("\nTotal: $count listed (filtered $filtered by name pattern)")
        else appendLine("\nTotal: $count functions")
    }

    /**
     * Returns a short annotation like " [note: external]" for functions that
     * are not project-owned. Returns "" for regular functions that should be
     * analyzed. Uses the same logic as VulnAuditHarness.shouldSkipFunction.
     */
    private fun classifyFunction(func: Function): String {
        if (func.isExternal) return " [note: external/imported]"
        if (func.isThunk) {
            val target = func.getThunkedFunction(false)
            return " [note: thunk → ${target?.name ?: "?"}]"
        }
        if (func.parentNamespace?.isLibrary == true) {
            return " [note: library function]"
        }
        val fname = func.name.lowercase()
        if (fname.endsWith("@plt") || fname.contains(".plt")) return " [note: PLT stub]"
        val name = fname.substringBefore('@')
        if (name.startsWith("__stack_chk_fail") || name == "__stack_chk_guard") return " [note: runtime helper]"
        if (name.startsWith("__cxa_") || name.startsWith("__gmon_") || name.startsWith("__libc_")) {
            return " [note: compiler/libc helper]"
        }
        if (name in ELF_COMPILER_HELPERS) return " [note: ELF compiler helper]"
        return ""
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
