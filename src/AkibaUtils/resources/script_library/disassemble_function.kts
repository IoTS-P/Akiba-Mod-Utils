// @name: disassemble_function
// @author: Akiba
// @description: Disassemble a function by name or address and return its assembly listing (one instruction per line, with addresses and bytes). Supports paging through large functions via 'addressAfter'.
// @parameters: target (string) - Function name or hex address (e.g. "main" or "0x401000"); showBytes (boolean, optional) - Include raw instruction bytes column (default: true); showComments (boolean, optional) - Include EOL/pre/post comments attached to instructions (default: true); addressAfter (string, optional) - If set, only emit instructions whose address is STRICTLY GREATER than this hex address. Use when a previous call's output was truncated by output size limits — pass the last address you saw to resume. Instructions outside the function body are skipped automatically.

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.CommentType

class DisassembleFunction : AkibaScript() {
    override suspend fun execute() {
        val target = scriptArgs["target"] as? String
            ?: run { appendLine("Error: 'target' parameter is required"); return }
        val showBytes = (scriptArgs["showBytes"] as? Boolean) ?: true
        val showComments = (scriptArgs["showComments"] as? Boolean) ?: true
        val addressAfterArg = scriptArgs["addressAfter"] as? String

        val program = currentProgram!!
        val fm = program.functionManager
        val listing = program.listing
        val addrFactory = program.addressFactory

        // Resolve target — try function name first, then hex address.
        // Iterate the FunctionIterator manually to avoid Iterable/Iterator
        // ambiguity when using .asSequence().
        var func: Function? = null
        val it = fm.getFunctions(true)
        while (it.hasNext()) {
            val f = it.next()
            if (f.name.equals(target, ignoreCase = true)) {
                func = f
                break
            }
        }

        if (func == null) {
            val addr = try {
                addrFactory.getAddress(target)
            } catch (_: Exception) { null }
            if (addr != null) {
                func = fm.getFunctionAt(addr) ?: fm.getFunctionContaining(addr)
            }
        }

        if (func == null) {
            appendLine("Error: Function '$target' not found")
            return
        }

        // Resolve the optional 'addressAfter' filter. Instructions whose
        // address is <= addressAfter are skipped.
        val addressAfter = if (addressAfterArg != null && addressAfterArg.isNotBlank()) {
            try {
                addrFactory.getAddress(addressAfterArg)
            } catch (_: Exception) {
                appendLine("Error: 'addressAfter' is not a valid address: $addressAfterArg")
                return
            }
        } else null

        appendLine("; Function: ${func.name} @ ${func.entryPoint}")
        appendLine("; Body: ${func.body.minAddress} - ${func.body.maxAddress}")
        if (addressAfter != null) {
            appendLine("; Resuming from instructions strictly after $addressAfter")
        }
        appendLine("")

        // Walk the function body and emit one line per instruction. Using
        // listing.getInstructions(AddressSetView, true) yields instructions in
        // address order across the (possibly non-contiguous) function body.
        val insnIter = listing.getInstructions(func.body, true)
        var count = 0
        var skippedByFilter = 0
        var lastEmittedAddr: ghidra.program.model.address.Address? = null
        while (insnIter.hasNext()) {
            val insn = insnIter.next()

            // Skip instructions at or before the resume point. compareTo
            // is defined on Ghidra Addresses within the same address space;
            // mismatched spaces fall back to "no skip" (treated as out of
            // scope for the filter).
            if (addressAfter != null) {
                val cmp = try { insn.address.compareTo(addressAfter) } catch (_: Exception) { 1 }
                if (cmp <= 0) {
                    skippedByFilter++
                    continue
                }
            }

            // Pre-comment (printed above the instruction).
            if (showComments) {
                insn.getComment(CommentType.PRE)?.let { c ->
                    c.lineSequence().forEach { line -> appendLine("    ; $line") }
                }
                insn.getComment(CommentType.PLATE)?.let { c ->
                    c.lineSequence().forEach { line -> appendLine("    ; $line") }
                }
            }

            val addrStr = insn.address.toString()
            val bytesStr = if (showBytes) {
                try {
                    val bytes = insn.bytes
                    val hex = bytes.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }
                    // Pad to a stable width (max 16 bytes shown = 47 chars + spaces).
                    hex.padEnd(24)
                } catch (_: Exception) { "".padEnd(24) }
            } else ""

            // Mnemonic + operand representation. toString() on an Instruction
            // gives the standard "mnemonic op1, op2, ..." formatting used by
            // Ghidra's listing.
            val asm = insn.toString()

            val eol = if (showComments) {
                insn.getComment(CommentType.EOL)?.let { "  ; $it" } ?: ""
            } else ""

            if (showBytes) {
                appendLine("$addrStr  $bytesStr  $asm$eol")
            } else {
                appendLine("$addrStr  $asm$eol")
            }

            // Post-comment (printed below the instruction).
            if (showComments) {
                insn.getComment(CommentType.POST)?.let { c ->
                    c.lineSequence().forEach { line -> appendLine("    ; $line") }
                }
            }

            lastEmittedAddr = insn.address
            count++
        }

        appendLine("")
        if (count == 0) {
            if (addressAfter != null && skippedByFilter > 0) {
                appendLine("; (no instructions emitted — all $skippedByFilter instruction(s) " +
                    "were at or before addressAfter=$addressAfter; the function ends here)")
            } else {
                appendLine("; (no instructions — function body may not be disassembled yet)")
            }
        } else {
            appendLine("; Total instructions emitted: $count" +
                if (skippedByFilter > 0) " (skipped $skippedByFilter before addressAfter)" else "")
            if (lastEmittedAddr != null) {
                appendLine("; Last emitted address: $lastEmittedAddr  " +
                    "(pass as 'addressAfter' to resume after a truncated output)")
            }
        }
    }
}
