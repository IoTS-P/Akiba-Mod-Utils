// @name: disassemble_function
// @author: Akiba
// @description: Disassemble instructions from a function, address range, or centered around an address. Supports three modes: (1) legacy — target a function by name/address; (2) range — specify startAddress + endAddress; (3) center — specify address + before + after. By default the output is restricted to a single function body; set force=true to cross function boundaries.
// @parameters: target (string, optional) - Legacy mode: function name or hex address (e.g. "main" or "0x401000"); startAddress (string, optional) - Range mode: start of disassembly range (hex); endAddress (string, optional) - Range mode: end of disassembly range (hex, inclusive); address (string, optional) - Center mode: the address to center around; before (integer, optional) - Center mode: instructions to show before the center address (default 8); after (integer, optional) - Center mode: instructions to show from/after the center address (default 24); showBytes (boolean, optional) - Include raw instruction bytes column (default: true); showComments (boolean, optional) - Include EOL/pre/post comments (default: true); addressAfter (string, optional) - Resume point: skip instructions at or before this address; force (boolean, optional) - Allow crossing function boundaries (default: false)

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Instruction

val MAX_RANGE_BYTES = 4096 // safety cap for any single call

class DisassembleFunction : AkibaScript() {

    // Package-level data class visible to all methods of this class
    data class RangeInfo(
        val rangeStart: Address,
        val rangeEnd: Address,
        val label: String
    )

    override suspend fun execute() {
        val program = currentProgram!!
        val listing = program.listing
        val addrFactory = program.addressFactory
        val fm = program.functionManager
        val showBytes = (scriptArgs["showBytes"] as? Boolean) ?: true
        val showComments = (scriptArgs["showComments"] as? Boolean) ?: true
        val addressAfterArg = scriptArgs["addressAfter"] as? String
        val force = (scriptArgs["force"] as? Boolean) ?: false

        // ── Step 1: Determine mode and compute instruction range ───────────
        val resolved: RangeInfo = when {
            // Range mode: startAddress + endAddress
            scriptArgs.containsKey("startAddress") || scriptArgs.containsKey("endAddress") -> {
                val startStr = scriptArgs["startAddress"] as? String
                    ?: run { appendLine("Error: 'startAddress' required in range mode"); return }
                val endStr = scriptArgs["endAddress"] as? String
                    ?: run { appendLine("Error: 'endAddress' required in range mode"); return }
                val start = parseAddr(startStr, addrFactory) ?: run { return }
                val end = parseAddr(endStr, addrFactory) ?: run { return }
                if (end < start) { appendLine("Error: endAddress ($endStr) < startAddress ($startStr)"); return }
                val size = end.subtract(start)
                if (size < 0 || size > MAX_RANGE_BYTES) {
                    appendLine("Error: range exceeds safety limit ($MAX_RANGE_BYTES bytes, got ${size} bytes). Narrow the range or use a more specific address.")
                    return
                }
                checkBoundary(start, end, fm, force) ?: return
                RangeInfo(start, end, "range $start - $end")
            }

            // Center mode: address + before + after
            scriptArgs.containsKey("address") -> {
                val addrStr = scriptArgs["address"] as? String
                    ?: run { appendLine("Error: 'address' required in center mode"); return }
                val center = parseAddr(addrStr, addrFactory) ?: run { return }
                val before = ((scriptArgs["before"] as? Number)?.toInt() ?: 8).coerceAtLeast(0)
                val after = ((scriptArgs["after"] as? Number)?.toInt() ?: 24).coerceAtLeast(1)

                var walk = listing.getInstructionAt(center) ?: listing.getInstructionAfter(center)
                    ?: run { appendLine("Error: no instruction at or after $center"); return }
                var walkBack = before
                while (walkBack > 0) {
                    val prev = listing.getInstructionBefore(walk.address)
                    if (prev == null) break
                    walk = prev
                    walkBack--
                }
                val walkStart = walk.address

                walk = listing.getInstructionAt(center) ?: listing.getInstructionAfter(center) ?: return
                var walkForward = after + before
                var lastAddr = walk.address
                while (walkForward > 0) {
                    val next = listing.getInstructionAfter(lastAddr)
                    if (next == null) break
                    lastAddr = next.address
                    walkForward--
                }

                val size = try { lastAddr.subtract(walkStart) } catch (_: Exception) { 0L }
                if (size > MAX_RANGE_BYTES) {
                    appendLine("Error: center mode range exceeds safety limit ($MAX_RANGE_BYTES bytes, got ${size} bytes). Reduce before/after values or use force=true.")
                    return
                }
                checkBoundary(walkStart, lastAddr, fm, force) ?: return
                RangeInfo(walkStart, lastAddr, "centered at $center")
            }

            // Legacy mode: target (function name or address)
            else -> {
                val target = scriptArgs["target"] as? String
                    ?: run { appendLine("Error: specify target (legacy), startAddress+endAddress (range), or address (center)"); return }
                resolveLegacy(target, fm, addrFactory) ?: return
            }
        }

        // ── Step 2: Resolve addressAfter ──────────────────────────────────
        val addressAfter = if (addressAfterArg != null && addressAfterArg.isNotBlank()) {
            parseAddr(addressAfterArg, addrFactory) ?: return
        } else null

        // ── Step 3: Emit instructions ──────────────────────────────────────
        appendLine("; Disassembly: ${resolved.label}")
        if (addressAfter != null) appendLine("; Resuming from instructions strictly after $addressAfter")
        appendLine("")

        val insnIter = listing.getInstructions(resolved.rangeStart, true)
        var count = 0
        var skippedByFilter = 0
        var lastEmittedAddr: Address? = null

        while (insnIter.hasNext()) {
            val insn = insnIter.next()
            if (insn.address > resolved.rangeEnd) break

            if (addressAfter != null) {
                val cmp = try { insn.address.compareTo(addressAfter) } catch (_: Exception) { 1 }
                if (cmp <= 0) { skippedByFilter++; continue }
            }

            if (showComments) {
                insn.getComment(CommentType.PRE)?.lineSequence()?.forEach { line -> appendLine("    ; $line") }
                insn.getComment(CommentType.PLATE)?.lineSequence()?.forEach { line -> appendLine("    ; $line") }
            }

            val addrStr = insn.address.toString()
            val bytesStr = if (showBytes) {
                try { insn.bytes.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }.padEnd(24) }
                catch (_: Exception) { "".padEnd(24) }
            } else ""

            val asm = insn.toString()
            val eol = if (showComments) {
                insn.getComment(CommentType.EOL)?.let { "  ; $it" } ?: ""
            } else ""

            appendLine(if (showBytes) "$addrStr  $bytesStr  $asm$eol" else "$addrStr  $asm$eol")

            if (showComments) {
                insn.getComment(CommentType.POST)?.lineSequence()?.forEach { line -> appendLine("    ; $line") }
            }

            lastEmittedAddr = insn.address
            count++
        }

        appendLine("")
        if (count == 0) {
            if (addressAfter != null && skippedByFilter > 0) {
                appendLine("; (no instructions emitted — all $skippedByFilter at or before addressAfter)")
            } else {
                appendLine("; (no instructions found in range)")
            }
        } else {
            appendLine("; Total instructions emitted: $count" +
                if (skippedByFilter > 0) " (skipped $skippedByFilter before addressAfter)" else "")
            if (lastEmittedAddr != null) {
                appendLine("; Last emitted address: $lastEmittedAddr" +
                    if (addressAfter == null) "  (pass as 'addressAfter' to resume)" else "")
            }
        }
    }

    // ── Helper: parse address ─────────────────────────────────────────────
    private fun parseAddr(s: String, af: ghidra.program.model.address.AddressFactory): Address? {
        return try { af.getAddress(s) } catch (_: Exception) {
            appendLine("Error: invalid address '$s'"); null
        }
    }

    // ── Helper: resolve legacy target ─────────────────────────────────────
    private fun resolveLegacy(target: String, fm: ghidra.program.model.listing.FunctionManager,
                              af: ghidra.program.model.address.AddressFactory): RangeInfo? {
        var func: Function? = null
        val iter = fm.getFunctions(true)
        while (iter.hasNext()) {
            val f = iter.next()
            if (f.name.equals(target, ignoreCase = true)) { func = f; break }
        }
        if (func == null) {
            val addr = try { af.getAddress(target) } catch (_: Exception) { null }
            if (addr != null) func = fm.getFunctionAt(addr) ?: fm.getFunctionContaining(addr)
        }
        if (func == null) {
            appendLine("Error: function '$target' not found")
            return null
        }
        appendLine("; Function: ${func.name} @ ${func.entryPoint}")
        appendLine("; Body: ${func.body.minAddress} - ${func.body.maxAddress}")
        return RangeInfo(func.body.minAddress, func.body.maxAddress, "function ${func.name}")
    }

    // ── Helper: enforce single-function boundary ──────────────────────────
    private fun checkBoundary(start: Address, end: Address,
                              fm: ghidra.program.model.listing.FunctionManager,
                              force: Boolean): RangeInfo? {
        if (force) return RangeInfo(start, end, "range $start - $end (forced)")

        // Overlapping functions using AddressSet
        val range = AddressSet(start, end)
        val bodyIter = fm.getFunctionsOverlapping(range)
        val funcs = mutableSetOf<String>()
        while (bodyIter.hasNext()) funcs.add(bodyIter.next().name)

        if (funcs.isEmpty()) {
            appendLine("Error: address range [$start - $end] does not belong to any function.")
            appendLine("  To disassemble outside function bodies, pass force=true.")
            return null
        }
        if (funcs.size > 1) {
            appendLine("Error: address range spans ${funcs.size} functions: ${funcs.joinToString(", ")}.")
            appendLine("  To disassemble across function boundaries, pass force=true.")
            return null
        }
        return RangeInfo(start, end, "in ${funcs.first()}")
    }
}
