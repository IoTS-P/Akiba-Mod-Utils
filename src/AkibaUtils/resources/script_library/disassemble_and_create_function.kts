// @name: disassemble_and_create_function
// @author: Akiba
// @description: Disassemble instructions starting from a given address and create a function there. Uses DisasmHelper to drive Ghidra's AutoAnalysisManager for disassembly, function creation, and follow-up analysis. Supports preset register values (e.g. ARM Cortex-M TMode=1 for Thumb mode selection) to guide disassembly on architectures where the instruction set depends on control registers. If a function already exists at the address, its info is reported without re-creating. On failure the disassembled code at the address is cleared automatically by DisasmHelper.
// @parameters: address (string) - Start address of the function to disassemble and create (hex, e.g. "0x401000"); presetRegisters (string, optional) - JSON object mapping register names to integer values, e.g. {"TMode":1} or {"TMode":"0x1"}. Used to guide disassembly on architectures where the instruction set depends on control registers (ARM Cortex-M Thumb mode, etc.). Register names are resolved via the program's language definition.
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import org.iotsplab.akiba.utils.assembly.DisasmHelper
import ghidra.program.model.listing.Function
import java.math.BigInteger

class DisassembleAndCreateFunction : AkibaScript() {
    override suspend fun execute() {
        val addressStr = scriptArgs["address"] as? String
            ?: run { appendLine("Error: 'address' parameter is required"); return }

        val start = try { program.addressFactory.getAddress(addressStr) }
            catch (_: Exception) { null }
            ?: run { appendLine("Error: invalid address '$addressStr'"); return }

        // ── If a function already exists here, just report it ────────────
        val existingFunc = program.functionManager.getFunctionAt(start)
        if (existingFunc != null) {
            appendLine("A function already exists at $start:")
            appendLine("  Name: ${existingFunc.name}")
            appendLine("  Entry: ${existingFunc.entryPoint}")
            appendLine("  Body: ${existingFunc.body.minAddress} - ${existingFunc.body.maxAddress}")
            appendLine("  Size: ${existingFunc.body.numAddresses} bytes")
            appendLine("  Signature: ${existingFunc.getPrototypeString(true, false)}")
            appendLine("  Calling convention: ${existingFunc.callingConventionName}")
            appendLine("  Is thunk: ${existingFunc.isThunk}")
            appendLine("")
            appendLine("(Use disassemble_function to view instructions, or manage_func_signature to modify the signature.)")
            return
        }

        // ── Validate the address is in an initialized memory block ───────
        val block = program.memory.getBlock(start)
        if (block == null) {
            appendLine("Error: address $start is not inside any memory block")
            return
        }
        if (!block.isInitialized) {
            appendLine("Error: address $start is in an uninitialized block '${block.name}' — cannot disassemble")
            return
        }

        // ── Parse optional preset register values ────────────────────────
        val presetRegsRaw = scriptArgs["presetRegisters"] as? String
        val presetRegs = LinkedHashMap<ghidra.program.model.lang.Register, BigInteger>()
        if (!presetRegsRaw.isNullOrBlank()) {
            @Suppress("UNCHECKED_CAST")
            val regMap: Map<String, Any?> = try {
                com.fasterxml.jackson.databind.ObjectMapper()
                    .readValue(presetRegsRaw, Map::class.java) as Map<String, Any?>
            } catch (e: Exception) {
                appendLine("Error: 'presetRegisters' is not a valid JSON object: ${e.message}")
                return
            }
            for ((regName, value) in regMap) {
                val reg = program.language.getRegister(regName)
                if (reg == null) {
                    appendLine("Error: register '$regName' not found in language ${program.languageID}")
                    appendLine("  Available registers can be queried via the QueryGhidraAPI tool:")
                    appendLine("    program.language.registers")
                    return
                }
                val bigVal = parseRegisterValue(value, regName) ?: return
                presetRegs[reg] = bigVal
            }
        }

        appendLine("=== Disassemble & Create Function ===")
        appendLine("Address: $start")
        appendLine("Block: ${block.name} (${block.start}-${block.end})")
        appendLine("Permissions: ${perms(block)}")
        if (presetRegs.isNotEmpty()) {
            appendLine("Preset registers:")
            presetRegs.forEach { (reg, value) ->
                appendLine("  ${reg.name} = $value (0x${value.toString(16)})")
            }
        }
        appendLine("")
        appendLine("Disassembling and creating function (this may take a moment)...")

        // ── Disassemble and create the function ──────────────────────────
        val helper = DisasmHelper(program)
        val monitor = taskGlobalMonitor

        val txId = program.startTransaction("disassemble_and_create_function @ $start")
        var committed = false
        var func: Function? = null
        try {
            func = helper.disasmFunction(start, presetRegs, monitor)
            committed = (func != null)
        } catch (e: Exception) {
            appendLine("Error: disassembly/creation failed: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, committed)
        }

        if (func == null) {
            appendLine("")
            appendLine("Failed to create function at $start.")
            appendLine("The disassembler may have cleared the code at this address. Common causes:")
            appendLine("  - The address does not point to valid executable code")
            appendLine("  - Incorrect or missing preset register (e.g. TMode for ARM Cortex-M Thumb mode)")
            appendLine("  - The memory block is not executable")
            appendLine("  - The code flow leads into unmapped memory")
            return
        }

        // ── Report the created function ──────────────────────────────────
        appendLine("")
        appendLine("Success! Function created:")
        appendLine("  Name: ${func.name}")
        appendLine("  Entry: ${func.entryPoint}")
        appendLine("  Body: ${func.body.minAddress} - ${func.body.maxAddress}")
        appendLine("  Size: ${func.body.numAddresses} bytes")
        appendLine("  Signature: ${func.getPrototypeString(true, false)}")
        appendLine("  Calling convention: ${func.callingConventionName}")
        appendLine("  Is thunk: ${func.isThunk}")
        appendLine("  Has custom storage: ${func.hasCustomVariableStorage()}")

        // ── Show the first few instructions ──────────────────────────────
        val insnIter = program.listing.getInstructions(func.body, true)
        val firstInstrs = mutableListOf<String>()
        var totalInstrs = 0
        while (insnIter.hasNext()) {
            val insn = insnIter.next()
            if (firstInstrs.size < 20) {
                val bytesStr = try {
                    insn.bytes.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }.padEnd(24)
                } catch (_: Exception) { "".padEnd(24) }
                firstInstrs.add("  ${insn.address}  $bytesStr  $insn")
            }
            totalInstrs++
        }

        appendLine("  Instructions: $totalInstrs")
        appendLine("")
        if (firstInstrs.isNotEmpty()) {
            appendLine("First ${minOf(20, totalInstrs)} instruction(s):")
            firstInstrs.forEach { appendLine(it) }
            if (totalInstrs > 20) {
                appendLine("  ... ($totalInstrs instructions total)")
                appendLine("  Use disassemble_function with startAddress=\"${func.entryPoint}\" to view more.")
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun parseRegisterValue(value: Any?, regName: String): BigInteger? {
        return when (value) {
            is Number -> BigInteger.valueOf(value.toLong())
            is String -> {
                val s = value.trim()
                try {
                    if (s.startsWith("0x", ignoreCase = true) || s.startsWith("-0x", ignoreCase = true)) {
                        val neg = s.startsWith("-")
                        val hexPart = s.substring(if (neg) 3 else 2)
                        val v = BigInteger(hexPart, 16)
                        if (neg) v.negate() else v
                    } else {
                        BigInteger(s)
                    }
                } catch (_: Exception) {
                    appendLine("Error: invalid value for register '$regName': '$value' (expected integer or hex string)")
                    null
                }
            }
            else -> {
                appendLine("Error: invalid value for register '$regName': $value (expected number or string)")
                null
            }
        }
    }

    private fun perms(block: ghidra.program.model.mem.MemoryBlock): String {
        return "" + (if (block.isRead) "r" else "-") +
               (if (block.isWrite) "w" else "-") +
               (if (block.isExecute) "x" else "-")
    }
}
