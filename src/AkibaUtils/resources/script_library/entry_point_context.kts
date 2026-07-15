// @name: entry_point_context
// @author: Akiba
// @description: Inspect instructions around program entry points and report the containing function for each entry address.
// @parameters: before (integer, optional) - number of instructions before each entry point to show, default 8; after (integer, optional) - number of instructions from/after each entry point to show, default 24; showBytes (boolean, optional) - include raw instruction bytes, default true; maxEntryPoints (integer, optional) - maximum entry points to inspect, default 8

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Instruction
import org.iotsplab.akiba.utils.binFormat.ELFStructures

class EntryPointContext : AkibaScript() {
    override suspend fun execute() {
        val program = this.program ?: run { appendLine("Error: no program loaded"); return }
        val listing = program.listing
        val fm = program.functionManager
        val before = ((scriptArgs["before"] as? Number)?.toInt() ?: 8).coerceAtLeast(0)
        val after = ((scriptArgs["after"] as? Number)?.toInt() ?: 24).coerceAtLeast(1)
        val showBytes = (scriptArgs["showBytes"] as? Boolean) ?: true
        val maxEntryPoints = ((scriptArgs["maxEntryPoints"] as? Number)?.toInt() ?: 8).coerceAtLeast(1)

        val entries = collectEntryPoints().distinct().take(maxEntryPoints)
        if (entries.isEmpty()) {
            appendLine("No entry point found from symbol table or ELF header.")
            return
        }

        appendLine("=== Entry Point Context ===")
        appendLine("Program: ${program.name}")
        appendLine("Entry points inspected: ${entries.size}")
        appendLine("Window: $before instruction(s) before, $after instruction(s) from/after entry")
        appendLine("")

        for ((idx, entry) in entries.withIndex()) {
            val func = fm.getFunctionAt(entry) ?: fm.getFunctionContaining(entry)
            appendLine("--- Entry #${idx + 1}: $entry ---")
            appendLine("Function: ${func?.name ?: "<no containing function>"}" +
                if (func != null) " @ ${func.entryPoint} body=${func.body.minAddress}-${func.body.maxAddress}" else "")
            appendLine("")

            // Walk backward with getInstructionBefore(), then forward from the
            // earliest collected instruction. This works even when the entry is
            // not exactly at a function boundary.
            val seed = listing.getInstructionAt(entry) ?: listing.getInstructionAfter(entry)
            if (seed == null) {
                appendLine("  (no instruction at or after entry)")
                appendLine("")
                continue
            }

            val prev = mutableListOf<Instruction>()
            var cur: Instruction? = seed
            while (cur != null && prev.size < before) {
                cur = listing.getInstructionBefore(cur!!.address)
                if (cur != null) prev.add(cur!!)
            }
            val ordered = prev.asReversed().toMutableList()
            cur = seed
            var emittedAfter = 0
            while (cur != null && emittedAfter < after) {
                ordered.add(cur!!)
                cur = listing.getInstructionAfter(cur!!.address)
                emittedAfter++
            }

            for (insn in ordered.distinctBy { it.address }) {
                val marker = if (insn.address == entry) "=>" else "  "
                appendLine(formatInstruction(marker, insn, showBytes))
            }
            appendLine("")
        }
    }

    private fun collectEntryPoints(): List<Address> {
        val program = this.program!!
        val result = mutableListOf<Address>()
        val it = program.symbolTable.getExternalEntryPointIterator()
        while (it.hasNext()) result.add(it.next())

        // ELF e_entry is useful when external entry point markup is absent.
        try {
            if (program.executableFormat.contains("ELF", ignoreCase = true)) {
                val elfEntry = ELFStructures(program).elfHeader.e_entry()
                if (elfEntry != 0L) {
                    result.add(program.addressFactory.defaultAddressSpace.getAddress(elfEntry))
                }
            }
        } catch (_: Exception) { }
        return result
    }

    private fun formatInstruction(marker: String, insn: Instruction, showBytes: Boolean): String {
        val bytes = if (showBytes) {
            try { insn.bytes.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }.padEnd(24) }
            catch (_: Exception) { "".padEnd(24) }
        } else ""
        val sep = if (showBytes) "  " else ""
        return "$marker ${insn.address}  $bytes$sep${insn}"
    }
}
