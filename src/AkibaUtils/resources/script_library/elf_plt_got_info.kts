// @name: elf_plt_got_info
// @author: Akiba
// @description: Report the PLT/GOT picture of an ELF program from what the loader analysed: the PLT and GOT blocks with their perms, the PLT stubs and what each one calls, the GOT slots that point at imported symbols, and the imported symbols themselves. Dynamic-table raw entries (DT_PLTGOT, DT_BIND_NOW) and segment-level RELRO flags are not exposed by the analysed program, so this reports the section-level view instead of guessing.
// @parameters: maxRelocations (integer, optional) - maximum GOT slots to print, default 80; showDynamicSymbols (boolean, optional) - print the imported symbols, default false; maxSymbols (integer, optional) - maximum symbols to print, default 120

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.mem.MemoryBlock

class ElfPltGotInfo : AkibaScript() {
    override suspend fun execute() {
        val program = this.program ?: run { appendLine("Error: no program loaded"); return }
        val maxRelocations = ((scriptArgs["maxRelocations"] as? Number)?.toInt() ?: 80).coerceAtLeast(1)
        val showSymbols = (scriptArgs["showDynamicSymbols"] as? Boolean) ?: false
        val maxSymbols = ((scriptArgs["maxSymbols"] as? Number)?.toInt() ?: 120).coerceAtLeast(1)

        appendLine("=== PLT/GOT Information ===")
        appendLine("Program: ${program.name}")
        appendLine("Format: ${program.executableFormat}")
        appendLine("Image base: ${program.imageBase}")
        appendLine("")

        val pltBlocks = blocksMatching(program, listOf(".plt", "plt", ".plt.sec"))
        val gotBlocks = blocksMatching(program, listOf(".got.plt", ".got", "got"))

        appendLine("=== Sections ===")
        for (block in (pltBlocks + gotBlocks).distinctBy { it.name }) {
            appendLine("  ${block.name.padEnd(12)} ${block.start}-${block.end}  ${perms(block)}")
        }
        if (pltBlocks.isEmpty() && gotBlocks.isEmpty()) {
            appendLine("  (no PLT or GOT block: statically linked, or stripped before loading)")
        }
        appendLine("")

        appendLine("=== PLT stubs ===")
        val stubs = pltBlocks.flatMap { functionsIn(it) }.distinctBy { it.entryPoint }
        if (stubs.isEmpty()) {
            appendLine("  (none found in the PLT block)")
        } else {
            for (stub in stubs.take(maxSymbols)) {
                // A PLT entry is usually a thunk the loader already named after
                // the imported symbol, so the name is the mapping.
                val kind = if (stub.isThunk) "thunk" else "stub"
                appendLine("  ${stub.entryPoint}  ${stub.name.padEnd(28)} $kind")
            }
            if (stubs.size > maxSymbols) appendLine("  ... (${stubs.size - maxSymbols} more)")
        }
        appendLine("")

        appendLine("=== GOT slots pointing at known symbols ===")
        var printed = 0
        var slots = 0
        for (block in gotBlocks) {
            val pointerSize = program.defaultPointerSize
            var addr: Address = block.start
            while (addr <= block.end && printed < maxRelocations) {
                slots++
                val value = runCatching { readPointer(program, addr, pointerSize) }.getOrNull()
                if (value != null) {
                    val symbol = program.symbolTable.getPrimarySymbol(value)
                    if (symbol != null) {
                        appendLine("  ${addr}  -> ${value}  ${symbol.name}")
                        printed++
                    }
                }
                addr = addr.add(pointerSize.toLong())
            }
        }
        if (slots == 0) {
            appendLine("  (no GOT block to read)")
        } else if (printed == 0) {
            appendLine("  (no slot points at a symbol the program knows)")
        }
        appendLine("")

        if (showSymbols) {
            appendLine("=== Imported symbols ===")
            val imported = importedSymbols(program).take(maxSymbols)
            if (imported.isEmpty()) {
                appendLine("  (none marked external)")
            } else {
                for ((name, addr) in imported) appendLine("  ${addr ?: "<no address>"}  $name")
            }
        }
    }

    private fun blocksMatching(
        program: ghidra.program.model.listing.Program,
        names: List<String>,
    ): List<MemoryBlock> = program.memory.blocks.filter { block ->
        names.any { wanted -> block.name.equals(wanted, ignoreCase = true) }
    }

    private fun functionsIn(block: MemoryBlock): List<Function> {
        val manager = program?.functionManager ?: return emptyList()
        val out = mutableListOf<Function>()
        val iter = manager.getFunctions(block.start, true)
        while (iter.hasNext()) {
            val f = iter.next()
            if (f.entryPoint > block.end) break
            out.add(f)
        }
        return out
    }

    private fun readPointer(
        program: ghidra.program.model.listing.Program,
        address: Address,
        size: Int,
    ): Address? {
        val raw = when (size) {
            8 -> program.memory.getLong(address)
            4 -> program.memory.getInt(address).toLong() and 0xffffffffL
            else -> return null
        }
        return program.addressFactory.getDefaultAddressSpace().getAddress(raw)
    }

    private fun importedSymbols(
        program: ghidra.program.model.listing.Program,
    ): List<Pair<String, Address?>> {
        val external = program.symbolTable.externalSymbols
        val out = mutableListOf<Pair<String, Address?>>()
        for (symbol in external) {
            out.add(symbol.name to null)
        }
        return out
    }

    private fun perms(block: MemoryBlock): String =
        (if (block.isRead) "r" else "-") +
            (if (block.isWrite) "w" else "-") +
            (if (block.isExecute) "x" else "-")
}
