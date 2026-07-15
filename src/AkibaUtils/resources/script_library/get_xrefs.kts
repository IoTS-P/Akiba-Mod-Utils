// @name: get_xrefs
// @author: Akiba
// @description: Get all cross-references (xrefs) to/from a function or address. IMPORTANT: 'target' must be a function name OR a hex address — string LITERALS are not accepted (string contents are not unique). To find xrefs to a string, first locate its address with 'search_strings', then pass that address here.
// @parameters: target (string) - Function name or hex address (e.g. "main" or "0x401000"). Do NOT pass a string literal/content — use 'search_strings' first to obtain the address; direction (string, optional) - "to", "from", or "both" (default: "both")

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.address.Address

class GetXrefs : AkibaScript() {
    override suspend fun execute() {
        val target = scriptArgs["target"] as? String
            ?: run { appendLine("Error: 'target' parameter is required"); return }
        val direction = (scriptArgs["direction"] as? String)?.lowercase() ?: "both"

        val fm = program!!.functionManager
        val refMgr = program!!.referenceManager

        // Reject obvious string-literal usage early. xrefs require an unambiguous
        // address or function name; string contents are NOT unique (the same
        // bytes can appear at many addresses in a binary), so we refuse them.
        // Heuristic: target is wrapped in quotes, or contains whitespace —
        // neither can occur in a real function symbol or hex address. We
        // intentionally do NOT enforce a strict character whitelist, because
        // mangled symbols can contain a wide variety of punctuation.
        val trimmed = target.trim()
        val looksLikeStringLiteral =
            (trimmed.length >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) ||
            (trimmed.length >= 2 && trimmed.startsWith("'") && trimmed.endsWith("'")) ||
            trimmed.any { it.isWhitespace() }
        if (looksLikeStringLiteral) {
            appendLine("Error: 'target' looks like a string literal (\"$target\").")
            appendLine("get_xrefs only accepts a function NAME or a hex ADDRESS, because")
            appendLine("a string's content is not unique — the same bytes may appear at")
            appendLine("many addresses in the binary.")
            appendLine("")
            appendLine("To find references to a string:")
            appendLine("  1. Run 'search_strings' with query=\"$target\" to list matching")
            appendLine("     strings and their addresses.")
            appendLine("  2. Pick the specific address you want, then call 'get_xrefs'")
            appendLine("     again with target=<that address>.")
            return
        }

        // Resolve target to an address — iterate FunctionIterator manually to avoid
        // Iterable/Iterator ambiguity when calling .asSequence().
        var resolvedAddr: Address? = null
        val iter = fm.getFunctions(true)
        while (iter.hasNext()) {
            val f = iter.next()
            if (f.name.equals(target, ignoreCase = true)) {
                resolvedAddr = f.entryPoint
                break
            }
        }

        if (resolvedAddr == null) {
            resolvedAddr = try {
                program!!.addressFactory.getAddress(target)
            } catch (_: Exception) { null }
        }

        if (resolvedAddr == null) {
            appendLine("Error: Cannot resolve '$target' to an address.")
            appendLine("Expected a function name or hex address (e.g. \"main\" or \"0x401000\").")
            appendLine("If you intended to find references to a string, use 'search_strings' first")
            appendLine("to obtain the string's address, then call get_xrefs with that address.")
            return
        }

        val addr: Address = resolvedAddr
        val func = fm.getFunctionAt(addr) ?: fm.getFunctionContaining(addr)
        appendLine("Cross-references for: ${func?.name ?: target} @ $addr")
        appendLine("")

        if (direction == "to" || direction == "both") {
            appendLine("=== References TO $addr ===")
            val refsTo = refMgr.getReferencesTo(addr)
            var countTo = 0
            refsTo.forEach { ref ->
                val caller = fm.getFunctionContaining(ref.fromAddress)
                appendLine("  ${caller?.name ?: "?"} @ ${ref.fromAddress} (${ref.referenceType})")
                countTo++
            }
            if (countTo == 0) appendLine("  (none)")
            appendLine("")
        }

        if (direction == "from" || direction == "both") {
            appendLine("=== References FROM ${func?.name ?: target} ===")
            if (func != null) {
                val body = func.body
                val refsFrom = mutableListOf<String>()
                val addrIter = body.getAddresses(true)
                while (addrIter.hasNext()) {
                    val a = addrIter.next()
                    refMgr.getReferencesFrom(a).forEach { ref ->
                        val callee = fm.getFunctionAt(ref.toAddress)
                        if (callee != null) {
                            refsFrom.add("  → ${callee.name} @ ${ref.toAddress} (${ref.referenceType})")
                        }
                    }
                }
                refsFrom.distinct().forEach { appendLine(it) }
                if (refsFrom.isEmpty()) appendLine("  (none)")
            } else {
                val refs = refMgr.getReferencesFrom(addr)
                if (refs.isEmpty()) {
                    appendLine("  (none)")
                } else {
                    refs.forEach { ref ->
                        val callee = fm.getFunctionAt(ref.toAddress)
                        appendLine("  → ${callee?.name ?: "?"} @ ${ref.toAddress} (${ref.referenceType})")
                    }
                }
            }
        }
    }
}
