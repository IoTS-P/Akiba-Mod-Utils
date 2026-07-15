// @name: list_memory_segments
// @author: Akiba
// @description: List all Ghidra memory blocks/segments with ranges, permissions, load/initialization status, and source names.
// @parameters: showUninitialized (boolean, optional) - include uninitialized blocks, default true; sortBy (string, optional) - address or name, default address

import org.iotsplab.akiba.script.AkibaScript

class ListMemorySegments : AkibaScript() {
    override suspend fun execute() {
        val program = this.program ?: run { appendLine("Error: no program loaded"); return }
        val showUninitialized = (scriptArgs["showUninitialized"] as? Boolean) ?: true
        val sortBy = ((scriptArgs["sortBy"] as? String) ?: "address").lowercase()

        val blocks = program.memory.blocks
            .filter { showUninitialized || it.isInitialized }
            .let { list -> if (sortBy == "name") list.sortedBy { it.name } else list.sortedBy { it.start } }

        appendLine("=== Memory Segments / Blocks ===")
        appendLine("Program: ${program.name}")
        appendLine("Count: ${blocks.size}")
        appendLine("")
        appendLine(String.format("%-24s %-18s %-18s %-12s %-5s %-6s %-6s %-14s %s",
            "Name", "Start", "End", "Size", "Perm", "Loaded", "Init", "Type", "Source"))
        appendLine("-".repeat(128))

        for (b in blocks) {
            appendLine(String.format("%-24s %-18s %-18s %-12s %-5s %-6s %-6s %-14s %s",
                b.name.take(24), b.start, b.end, "0x${b.size.toString(16)}", perms(b),
                b.isLoaded.toString(), b.isInitialized.toString(), b.type.toString(), b.sourceName ?: ""))
        }
    }

    private fun perms(block: ghidra.program.model.mem.MemoryBlock): String {
        return "" + (if (block.isRead) "r" else "-") + (if (block.isWrite) "w" else "-") + (if (block.isExecute) "x" else "-")
    }
}
