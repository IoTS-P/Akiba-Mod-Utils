// @name: emulate
// @author: Akiba
// @description: Emulate execution of a code region using Ghidra's PcodeEmulator. Initializes memory from the current program, sets up a stack, applies user-specified register/memory values, and executes until an end address is reached, an error occurs, or limits are hit. External function calls (thunks) are automatically stubbed to return 0. Provides detailed failure reasons when emulation cannot continue.
// @parameters: address (string, required) - Start address (hex, e.g. "0x401000") or function name; maxInstructions (integer, optional) - Maximum instructions to execute (default 1000, max 100000); registers (string, optional) - JSON object mapping register names to hex values, e.g. {"RAX":"0x1000","RBX":"0x2000"}; memory (string, optional) - JSON object mapping hex addresses to hex byte strings, e.g. {"0x1000":"01020304"}; endAddresses (string, optional) - JSON array of hex addresses or function names; emulation stops when PC reaches any of them. If omitted, stops on maxInstructions/timeout/error; traceFile (string, optional) - Path to trace output file (relative to workspace). If set, every executed instruction is logged. If omitted, no trace is recorded; traceRW (boolean, optional) - Record all memory read/write operations in the trace file (default false). Requires traceFile to be set; timeout (integer, optional) - Timeout in seconds (default 60, max 300); stackSize (integer, optional) - Stack size in bytes (default 65536); returnValue (string, optional) - Hex value to return from stubbed external calls (default "0x0")
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import ghidra.pcode.emu.PcodeEmulator
import ghidra.pcode.emu.PcodeEmulationCallbacks
import ghidra.pcode.emu.PcodeMachine
import ghidra.pcode.emu.PcodeThread
import ghidra.pcode.exec.PcodeExecutorStatePiece
import ghidra.pcode.exec.PcodeFrame
import ghidra.pcode.exec.PcodeProgram
import ghidra.pcode.exec.PcodeUseropLibrary
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.lang.Register
import ghidra.program.model.lang.RegisterValue
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.mem.MemoryBlock
import ghidra.program.model.pcode.PcodeOp
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter

class Emulate : AkibaScript() {

    // ── Result types ───────────────────────────────────────────────────

    sealed class EmuResult {
        abstract val instructionsExecuted: Int
        abstract val finalPC: Address?

        data class EndAddressReached(
            override val instructionsExecuted: Int,
            override val finalPC: Address,
            val endAddress: Address
        ) : EmuResult()

        data class MaxInstructionsReached(
            override val instructionsExecuted: Int,
            override val finalPC: Address
        ) : EmuResult()

        data class Timeout(
            override val instructionsExecuted: Int,
            override val finalPC: Address?
        ) : EmuResult()

        data class ExternalCallStubbed(
            override val instructionsExecuted: Int,
            override val finalPC: Address,
            val thunkAddress: Address,
            val targetFunction: String,
            val returnValue: Long
        ) : EmuResult()

        data class UninitializedMemoryRead(
            override val instructionsExecuted: Int,
            override val finalPC: Address,
            val readAddress: Address,
            val size: Int
        ) : EmuResult()

        data class InvalidAddress(
            override val instructionsExecuted: Int,
            override val finalPC: Address?,
            val invalidAddress: Address,
            val reason: String
        ) : EmuResult()

        data class UnknownInstruction(
            override val instructionsExecuted: Int,
            override val finalPC: Address,
            val bytes: ByteArray
        ) : EmuResult()

        data class SyscallEncountered(
            override val instructionsExecuted: Int,
            override val finalPC: Address
        ) : EmuResult()

        data class BreakpointHit(
            override val instructionsExecuted: Int,
            override val finalPC: Address
        ) : EmuResult()

        data class EmulatorError(
            override val instructionsExecuted: Int,
            override val finalPC: Address?,
            val errorType: String,
            val message: String,
            val cause: String?
        ) : EmuResult()
    }

    // ── Tracking state ─────────────────────────────────────────────────

    private data class StackInfo(
        val base: Address,
        val top: Address,
        val initialSP: Address,
        val returnMarker: Address
    )

    private val warnings = mutableListOf<String>()

    // ── Trace callbacks ────────────────────────────────────────────────

    /**
     * Trace writer that records every executed instruction and optionally
     * all memory read/write operations to a file.
     *
     * Uses a [BufferedWriter] with immediate flush after each entry to
     * minimize data loss if emulation crashes mid-run.
     */
    private inner class TraceWriter(
        private val writer: BufferedWriter,
        private val traceRW: Boolean
    ) {
        private var insnCount = 0

        fun logInstruction(pc: Address, instruction: String) {
            insnCount++
            writer.write("[$insnCount] INSN $pc: $instruction\n")
            writer.flush()
        }

        fun logRead(addr: Address, size: Int, value: ByteArray) {
            if (traceRW) {
                writer.write("[$insnCount] READ  $addr: $size bytes = ${value.toHex()}\n")
                writer.flush()
            }
        }

        fun logWrite(addr: Address, size: Int, value: ByteArray) {
            if (traceRW) {
                writer.write("[$insnCount] WRITE $addr: $size bytes = ${value.toHex()}\n")
                writer.flush()
            }
        }

        fun logComment(text: String) {
            writer.write("# $text\n")
            writer.flush()
        }

        fun close() {
            try { writer.close() } catch (_: Exception) {}
        }
    }

    /**
     * Adapter for [PcodeEmulationCallbacks] that forwards instruction
     * execution and memory access events to a [TraceWriter].
     *
     * All 24 interface methods are implemented; only the ones relevant
     * to tracing have non-trivial bodies.
     */
    private inner class TraceCallbacks(
        private val tracer: TraceWriter
    ) : PcodeEmulationCallbacks<ByteArray> {

        // ── Machine lifecycle ──
        override fun emulatorCreated(machine: PcodeMachine<ByteArray>) {}
        override fun sharedStateCreated(machine: PcodeMachine<ByteArray>) {}
        override fun threadCreated(thread: PcodeThread<ByteArray>) {}

        // ── Injection ──
        override fun getInject(thread: PcodeThread<ByteArray>, address: Address): PcodeProgram? = null
        override fun beforeExecuteInject(thread: PcodeThread<ByteArray>, address: Address, program: PcodeProgram) {}
        override fun afterExecuteInject(thread: PcodeThread<ByteArray>, address: Address) {}

        // ── Instruction decode/execute ──
        override fun beforeDecodeInstruction(thread: PcodeThread<ByteArray>, counter: Address, context: RegisterValue) {}
        override fun beforeExecuteInstruction(thread: PcodeThread<ByteArray>, instruction: Instruction, program: PcodeProgram) {}
        override fun afterExecuteInstruction(thread: PcodeThread<ByteArray>, instruction: Instruction) {
            tracer.logInstruction(instruction.address, instruction.toString())
        }

        // ── P-code op stepping ──
        override fun beforeStepOp(thread: PcodeThread<ByteArray>, op: PcodeOp, frame: PcodeFrame) {}
        override fun afterStepOp(thread: PcodeThread<ByteArray>, op: PcodeOp, frame: PcodeFrame) {}

        // ── Memory load/store ──
        override fun beforeLoad(thread: PcodeThread<ByteArray>, op: PcodeOp, space: AddressSpace, offset: ByteArray, size: Int) {}
        override fun afterLoad(thread: PcodeThread<ByteArray>, op: PcodeOp, space: AddressSpace, offset: ByteArray, size: Int, value: ByteArray) {
            val addr = space.getAddress(bytesToLong(offset))
            tracer.logRead(addr, size, value)
        }
        override fun beforeStore(thread: PcodeThread<ByteArray>, op: PcodeOp, space: AddressSpace, offset: ByteArray, size: Int, value: ByteArray) {}
        override fun afterStore(thread: PcodeThread<ByteArray>, op: PcodeOp, space: AddressSpace, offset: ByteArray, size: Int, value: ByteArray) {
            val addr = space.getAddress(bytesToLong(offset))
            tracer.logWrite(addr, size, value)
        }

        // ── Branch ──
        override fun afterBranch(thread: PcodeThread<ByteArray>, op: PcodeOp, target: Address) {}

        // ── Userop ──
        override fun handleMissingUserop(thread: PcodeThread<ByteArray>, op: PcodeOp, frame: PcodeFrame, opName: String, library: PcodeUseropLibrary<ByteArray>): Boolean = false

        // ── State piece callbacks (generic, not used for tracing) ──
        override fun <A, U> dataWritten(thread: PcodeThread<ByteArray>?, piece: PcodeExecutorStatePiece<A, U>, space: AddressSpace, offset: A, length: Int, value: U) {}
        override fun <A, U> delegateDataWritten(thread: PcodeThread<ByteArray>?, piece: PcodeExecutorStatePiece<A, U>, space: AddressSpace, offset: A, length: Int, value: U) {}
        override fun <A, U> dataWritten(thread: PcodeThread<ByteArray>?, piece: PcodeExecutorStatePiece<A, U>, address: Address, length: Int, value: U) {}
        override fun <A, U> delegateDataWritten(thread: PcodeThread<ByteArray>?, piece: PcodeExecutorStatePiece<A, U>, address: Address, length: Int, value: U) {}
        override fun <A, U> readUninitialized(thread: PcodeThread<ByteArray>?, piece: PcodeExecutorStatePiece<A, U>, space: AddressSpace, offset: A, length: Int, reason: PcodeExecutorStatePiece.Reason): Int = 0
        override fun <A, U> delegateReadUninitialized(thread: PcodeThread<ByteArray>?, piece: PcodeExecutorStatePiece<A, U>, space: AddressSpace, offset: A, length: Int, reason: PcodeExecutorStatePiece.Reason): Int = 0
        override fun <A, U> readUninitialized(thread: PcodeThread<ByteArray>?, piece: PcodeExecutorStatePiece<A, U>, set: AddressSetView, reason: PcodeExecutorStatePiece.Reason): AddressSetView = set
        override fun <A, U> delegateReadUninitialized(thread: PcodeThread<ByteArray>?, piece: PcodeExecutorStatePiece<A, U>, set: AddressSetView, reason: PcodeExecutorStatePiece.Reason): AddressSetView = set
    }

    // ── Main entry ─────────────────────────────────────────────────────

    override suspend fun execute() {
        val prog = program ?: run { appendLine("Error: no program loaded"); return }

        // ── Parse parameters ──
        val addressStr = scriptArgs["address"] as? String
            ?: run { appendLine("Error: 'address' parameter is required"); return }
        val maxInstructions = ((scriptArgs["maxInstructions"] as? Number)?.toInt() ?: 1000)
            .coerceIn(1, 100_000)
        val timeoutSec = ((scriptArgs["timeout"] as? Number)?.toInt() ?: 60)
            .coerceIn(10, 300)
        val traceRW = scriptArgs["traceRW"] as? Boolean ?: false
        val stackSize = ((scriptArgs["stackSize"] as? Number)?.toInt() ?: 65536)
            .coerceIn(4096, 1_048_576)
        val returnValueStr = (scriptArgs["returnValue"] as? String) ?: "0x0"
        val returnValue = parseHexLong(returnValueStr) ?: 0L

        // ── Trace file setup ──
        val traceFilePath = (scriptArgs["traceFile"] as? String)?.takeIf { it.isNotBlank() }
        if (traceRW && traceFilePath == null) {
            appendLine("Error: 'traceRW' requires 'traceFile' to be specified.")
            appendLine("  Memory read/write tracing produces a large volume of entries;")
            appendLine("  they must be written to a file rather than returned in the result.")
            return
        }

        var traceWriter: TraceWriter? = null
        if (traceFilePath != null) {
            val wsDirStr = (scriptArgs["_akiba_workspace_dir"] as? String)
                ?: workspaceDir.toString()
            val traceFile = if (File(traceFilePath).isAbsolute) {
                File(traceFilePath)
            } else {
                File(wsDirStr, traceFilePath)
            }
            try {
                traceFile.parentFile?.mkdirs()
                traceWriter = TraceWriter(BufferedWriter(FileWriter(traceFile)), traceRW)
                traceWriter.logComment("Akiba Emulation Trace")
                traceWriter.logComment("Start: $addressStr")
                traceWriter.logComment("Max instructions: $maxInstructions")
                traceWriter.logComment("Trace RW: $traceRW")
                appendLine("Trace file: ${traceFile.absolutePath}")
            } catch (e: Exception) {
                appendLine("Error: failed to open trace file '${traceFile.absolutePath}': ${e.message}")
                return
            }
        }

        // Parse end addresses
        val endAddresses = parseEndAddresses(scriptArgs["endAddresses"] as? String)

        // ── Resolve start address ──
        val startAddr = resolveAddress(prog, addressStr)
        if (startAddr == null) {
            appendLine("Error: cannot resolve address '$addressStr'")
            return
        }

        appendLine("=== Ghidra PcodeEmulator ===")
        appendLine("Program: ${prog.name}")
        appendLine("Start: $startAddr")
        appendLine("Max instructions: $maxInstructions")
        appendLine("Timeout: ${timeoutSec}s")
        if (endAddresses.isNotEmpty()) {
            appendLine("End addresses: ${endAddresses.joinToString(", ") { it.toString() }}")
        }
        appendLine("Trace RW: $traceRW")
        appendLine("")

        // ── Create emulator (with trace callbacks if trace file is set) ──
        val emulator = if (traceWriter != null) {
            PcodeEmulator(prog.language, TraceCallbacks(traceWriter))
        } else {
            PcodeEmulator(prog.language)
        }
        val thread = emulator.newThread()

        // ── Initialize memory from program ──
        appendLine("Initializing memory from program...")
        val memInitResult = initializeMemory(emulator, prog)
        appendLine("  ${memInitResult.blocksCopied} blocks copied, ${memInitResult.bytesCopied} bytes")
        if (memInitResult.skippedBlocks > 0) {
            appendLine("  ${memInitResult.skippedBlocks} uninitialized blocks skipped")
        }

        // ── Initialize stack ──
        appendLine("Initializing stack (${stackSize} bytes)...")
        val stackInfo = initializeStack(emulator, thread, prog, stackSize)
        appendLine("  Stack: ${stackInfo.base} - ${stackInfo.top}")
        appendLine("  SP = ${stackInfo.initialSP}")
        appendLine("  Return marker: ${stackInfo.returnMarker}")

        // ── Apply user-specified registers ──
        val registersJson = scriptArgs["registers"] as? String
        if (!registersJson.isNullOrBlank()) {
            appendLine("Applying register overrides...")
            applyRegisters(thread, prog, registersJson)
        }

        // ── Apply user-specified memory ──
        val memoryJson = scriptArgs["memory"] as? String
        if (!memoryJson.isNullOrBlank()) {
            appendLine("Applying memory overrides...")
            applyMemory(emulator, prog, memoryJson)
        }

        // ── Set PC ──
        thread.overrideCounter(startAddr)

        // ── Run emulation ──
        appendLine("")
        appendLine("Starting emulation...")
        val result = runEmulation(
            emulator, thread, prog,
            startAddr, endAddresses, maxInstructions,
            timeoutSec, stackInfo, returnValue
        )

        // ── Output results ──
        appendLine("")
        outputResult(emulator, thread, prog, result)

        // ── Close trace file ──
        traceWriter?.let {
            it.logComment("End of trace")
            it.logComment("Result: ${result.javaClass.simpleName}")
            it.logComment("Instructions: ${result.instructionsExecuted}")
            it.close()
            appendLine("Trace written to: $traceFilePath")
        }
    }

    // ── Memory initialization ──────────────────────────────────────────

    private data class MemInitResult(
        val blocksCopied: Int,
        val bytesCopied: Long,
        val skippedBlocks: Int
    )

    private fun initializeMemory(
        emulator: PcodeEmulator,
        prog: ghidra.program.model.listing.Program
    ): MemInitResult {
        val sharedState = emulator.sharedState
        var blocksCopied = 0
        var bytesCopied = 0L
        var skippedBlocks = 0

        for (block in prog.memory.blocks) {
            if (!block.isInitialized) {
                skippedBlocks++
                continue
            }
            try {
                val size = block.size.toInt()
                if (size <= 0) continue
                val bytes = ByteArray(size)
                prog.memory.getBytes(block.start, bytes)
                sharedState.setVar(block.start, size, false, bytes)
                blocksCopied++
                bytesCopied += size
            } catch (e: Exception) {
                warnings.add("Failed to initialize block ${block.name}: ${e.message}")
            }
        }
        return MemInitResult(blocksCopied, bytesCopied, skippedBlocks)
    }

    // ── Stack initialization ───────────────────────────────────────────

    private fun initializeStack(
        emulator: PcodeEmulator,
        thread: PcodeThread<ByteArray>,
        prog: ghidra.program.model.listing.Program,
        stackSize: Int
    ): StackInfo {
        val pointerSize = prog.defaultPointerSize
        val spReg = prog.compilerSpec.stackPointer

        // Find a suitable stack base: use the highest address in the default space
        // and go beyond it by a safe margin.
        val defaultSpace = prog.addressFactory.defaultAddressSpace
        val maxAddr = prog.maxAddress
        val stackBase = maxAddr.add(0x10000)  // 64KB above program end
        val stackTop = stackBase.add(stackSize.toLong() - 1)

        // Zero-fill the stack
        val zeros = ByteArray(stackSize)
        emulator.sharedState.setVar(stackBase, stackSize, false, zeros)

        // Set SP to top of stack minus space for return address
        val initialSP = stackTop.subtract(pointerSize.toLong() - 1)
        val spBytes = addressToBytes(initialSP, pointerSize)
        thread.state.setVar(spReg, spBytes)

        // Write a return marker at the initial SP location
        // When the emulated function "returns", it will jump to this marker.
        // We use an address that's guaranteed to be invalid (outside any memory block).
        val returnMarker = defaultSpace.getAddress(0xDEADBEEFL)
        val markerBytes = addressToBytes(returnMarker, pointerSize)
        emulator.sharedState.setVar(initialSP, pointerSize, false, markerBytes)

        return StackInfo(stackBase, stackTop, initialSP, returnMarker)
    }

    // ── Register / memory overrides ────────────────────────────────────

    private fun applyRegisters(
        thread: PcodeThread<ByteArray>,
        prog: ghidra.program.model.listing.Program,
        json: String
    ) {
        val map = try {
            com.fasterxml.jackson.databind.ObjectMapper().readValue(json, Map::class.java)
        } catch (e: Exception) {
            appendLine("  Warning: failed to parse registers JSON: ${e.message}")
            return
        }

        for ((key, value) in map) {
            val regName = key.toString()
            val valueStr = value.toString()
            val reg = prog.getRegister(regName)
            if (reg == null) {
                appendLine("  Warning: unknown register '$regName'")
                continue
            }
            val value = parseHexLong(valueStr)
            if (value == null) {
                appendLine("  Warning: invalid hex value '$valueStr' for register '$regName'")
                continue
            }
            val bytes = longToBytes(value, reg.numBytes)
            thread.state.setVar(reg, bytes)
            appendLine("  $regName = 0x${value.toString(16).uppercase()}")
        }
    }

    private fun applyMemory(
        emulator: PcodeEmulator,
        prog: ghidra.program.model.listing.Program,
        json: String
    ) {
        val map = try {
            com.fasterxml.jackson.databind.ObjectMapper().readValue(json, Map::class.java)
        } catch (e: Exception) {
            appendLine("  Warning: failed to parse memory JSON: ${e.message}")
            return
        }

        for ((key, value) in map) {
            val addrStr = key.toString()
            val hexStr = value.toString().replace(" ", "").replace("0x", "")
            val addr = resolveAddress(prog, addrStr)
            if (addr == null) {
                appendLine("  Warning: cannot resolve address '$addrStr'")
                continue
            }
            val bytes = hexToBytes(hexStr)
            if (bytes == null) {
                appendLine("  Warning: invalid hex bytes '$hexStr' for address '$addrStr'")
                continue
            }
            emulator.sharedState.setVar(addr, bytes.size, false, bytes)
            appendLine("  [$addrStr] = ${bytes.size} bytes written")
        }
    }

    // ── Emulation loop ─────────────────────────────────────────────────

    private fun runEmulation(
        emulator: PcodeEmulator,
        thread: PcodeThread<ByteArray>,
        prog: ghidra.program.model.listing.Program,
        startAddr: Address,
        endAddresses: Set<Address>,
        maxInstructions: Int,
        timeoutSec: Int,
        stackInfo: StackInfo,
        returnValue: Long
    ): EmuResult {
        var instructionsExecuted = 0
        val startTime = System.currentTimeMillis()
        val timeoutMs = timeoutSec * 1000L

        while (instructionsExecuted < maxInstructions) {
            // Check timeout
            val elapsed = System.currentTimeMillis() - startTime
            if (elapsed > timeoutMs) {
                return EmuResult.Timeout(instructionsExecuted, thread.counter)
            }

            val currentPC = thread.counter

            // Check end addresses
            if (currentPC in endAddresses) {
                return EmuResult.EndAddressReached(instructionsExecuted, currentPC, currentPC)
            }

            // Check if we hit the return marker (function returned)
            if (currentPC == stackInfo.returnMarker) {
                return EmuResult.EndAddressReached(instructionsExecuted, currentPC, currentPC)
            }

            // Check if current address is a thunk (external call)
            val func = prog.functionManager.getFunctionAt(currentPC)
            if (func != null && func.isThunk) {
                val stubResult = stubExternalCall(emulator, thread, prog, func, returnValue, stackInfo)
                if (stubResult != null) {
                    return stubResult.copy(instructionsExecuted = instructionsExecuted)
                }
                // Stub succeeded, continue from return address
                instructionsExecuted++  // Count the stub as one instruction
                continue
            }

            // Check if address is valid (inside a memory block)
            val block = prog.memory.getBlock(currentPC)
            if (block == null) {
                return EmuResult.InvalidAddress(
                    instructionsExecuted, currentPC, currentPC,
                    "Address is not inside any memory block"
                )
            }

            // Try to execute one instruction
            try {
                thread.stepInstruction()
                instructionsExecuted++
            } catch (e: Exception) {
                return classifyError(e, instructionsExecuted, currentPC, prog)
            }
        }

        return EmuResult.MaxInstructionsReached(instructionsExecuted, thread.counter)
    }

    // ── External call stubbing ─────────────────────────────────────────

    private fun stubExternalCall(
        emulator: PcodeEmulator,
        thread: PcodeThread<ByteArray>,
        prog: ghidra.program.model.listing.Program,
        thunkFunc: Function,
        returnValue: Long,
        stackInfo: StackInfo
    ): EmuResult.ExternalCallStubbed? {
        val pointerSize = prog.defaultPointerSize
        val spReg = prog.compilerSpec.stackPointer
        // Get the default return register from the default calling convention.
        // This is more reliable than hardcoding RAX/EAX/r0.
        val retReg = try {
            val defaultCC = prog.compilerSpec.defaultCallingConvention
            val retStorage = defaultCC?.getReturnLocation(null, prog)
            if (retStorage != null && retStorage.isRegisterStorage) retStorage.register else null
        } catch (_: Exception) { null }

        try {
            // Read current SP
            val spBytes = thread.state.getVar(spReg, PcodeExecutorStatePiece.Reason.INSPECT)
            val spValue = bytesToLong(spBytes)
            val spAddr = prog.addressFactory.defaultAddressSpace.getAddress(spValue)

            // Read return address from stack
            val retBytes = emulator.sharedState.getVar(
                spAddr, pointerSize, false,
                PcodeExecutorStatePiece.Reason.INSPECT
            )
            val retAddrValue = bytesToLong(retBytes)
            val retAddr = prog.addressFactory.defaultAddressSpace.getAddress(retAddrValue)

            // Set return register to specified value
            if (retReg != null) {
                val retBytesVal = longToBytes(returnValue, retReg.numBytes)
                thread.state.setVar(retReg, retBytesVal)
            }

            // Pop stack (SP += pointerSize)
            val newSP = spValue + pointerSize
            val newSPBytes = longToBytes(newSP, pointerSize)
            thread.state.setVar(spReg, newSPBytes)

            // Jump to return address
            thread.overrideCounter(retAddr)

            // If return address is the marker, we're done
            if (retAddr == stackInfo.returnMarker) {
                return EmuResult.ExternalCallStubbed(
                    0, retAddr, thunkFunc.entryPoint,
                    thunkFunc.name, returnValue
                )
            }

            return null  // Continue emulation
        } catch (e: Exception) {
            return EmuResult.ExternalCallStubbed(
                0, thunkFunc.entryPoint, thunkFunc.entryPoint,
                thunkFunc.name, returnValue
            ).also {
                warnings.add("Failed to stub external call to ${thunkFunc.name}: ${e.message}")
            }
        }
    }

    // ── Error classification ───────────────────────────────────────────

    private fun classifyError(
        e: Exception,
        instructionsExecuted: Int,
        currentPC: Address,
        prog: ghidra.program.model.listing.Program
    ): EmuResult {
        val msg = e.message ?: ""
        val cause = e.cause?.message

        return when {
            // Uninitialized memory read
            msg.contains("uninitialized", ignoreCase = true) ||
            msg.contains("Uninitialized", ignoreCase = true) -> {
                // Try to extract address from error message
                EmuResult.UninitializedMemoryRead(
                    instructionsExecuted, currentPC, currentPC, 0
                )
            }

            // Instruction decode failure
            msg.contains("decode", ignoreCase = true) ||
            msg.contains("instruction", ignoreCase = true) ||
            e.javaClass.simpleName.contains("Decode") -> {
                val bytes = try {
                    val block = prog.memory.getBlock(currentPC)
                    if (block != null && block.isInitialized) {
                        val size = minOf(16, block.size.toInt())
                        val buf = ByteArray(size)
                        prog.memory.getBytes(currentPC, buf)
                        buf
                    } else ByteArray(0)
                } catch (_: Exception) { ByteArray(0) }
                EmuResult.UnknownInstruction(instructionsExecuted, currentPC, bytes)
            }

            // Invalid address / access violation
            msg.contains("address", ignoreCase = true) ||
            msg.contains("memory", ignoreCase = true) ||
            msg.contains("access", ignoreCase = true) -> {
                EmuResult.InvalidAddress(
                    instructionsExecuted, currentPC, currentPC,
                    msg.take(200)
                )
            }

            // Syscall / SWI
            msg.contains("syscall", ignoreCase = true) ||
            msg.contains("swi", ignoreCase = true) ||
            msg.contains("interrupt", ignoreCase = true) -> {
                EmuResult.SyscallEncountered(instructionsExecuted, currentPC)
            }

            // Breakpoint
            msg.contains("breakpoint", ignoreCase = true) -> {
                EmuResult.BreakpointHit(instructionsExecuted, currentPC)
            }

            // Generic emulator error
            else -> {
                EmuResult.EmulatorError(
                    instructionsExecuted, currentPC,
                    e.javaClass.simpleName,
                    msg.take(500),
                    cause?.take(200)
                )
            }
        }
    }

    // ── Result output ──────────────────────────────────────────────────

    private fun outputResult(
        emulator: PcodeEmulator,
        thread: PcodeThread<ByteArray>,
        prog: ghidra.program.model.listing.Program,
        result: EmuResult
    ) {
        appendLine("=== Emulation Result ===")
        appendLine("")

        // Status
        when (result) {
            is EmuResult.EndAddressReached -> {
                appendLine("Status: SUCCESS — reached end address ${result.endAddress}")
            }
            is EmuResult.MaxInstructionsReached -> {
                appendLine("Status: STOPPED — reached maximum instruction count")
            }
            is EmuResult.Timeout -> {
                appendLine("Status: TIMEOUT — exceeded time limit")
            }
            is EmuResult.ExternalCallStubbed -> {
                appendLine("Status: STOPPED — external call stubbed")
                appendLine("  Thunk: ${result.targetFunction} @ ${result.thunkAddress}")
                appendLine("  Return value: 0x${result.returnValue.toString(16).uppercase()}")
            }
            is EmuResult.UninitializedMemoryRead -> {
                appendLine("Status: FAILED — uninitialized memory read")
                appendLine("  Read address: ${result.readAddress}")
                appendLine("  Size: ${result.size} bytes")
                appendLine("  Tip: Initialize this memory region using the 'memory' parameter")
            }
            is EmuResult.InvalidAddress -> {
                appendLine("Status: FAILED — invalid address")
                appendLine("  Address: ${result.invalidAddress}")
                appendLine("  Reason: ${result.reason}")
            }
            is EmuResult.UnknownInstruction -> {
                appendLine("Status: FAILED — unknown instruction")
                appendLine("  Address: ${result.finalPC}")
                if (result.bytes.isNotEmpty()) {
                    appendLine("  Bytes: ${result.bytes.joinToString(" ") { "%02x".format(it) }}")
                }
                appendLine("  Tip: The instruction may be data, or the address may be misaligned")
            }
            is EmuResult.SyscallEncountered -> {
                appendLine("Status: FAILED — syscall encountered")
                appendLine("  Address: ${result.finalPC}")
                appendLine("  Tip: Syscalls are not supported by the emulator. Stub the calling function.")
            }
            is EmuResult.BreakpointHit -> {
                appendLine("Status: STOPPED — breakpoint hit")
                appendLine("  Address: ${result.finalPC}")
            }
            is EmuResult.EmulatorError -> {
                appendLine("Status: FAILED — emulator error")
                appendLine("  Error type: ${result.errorType}")
                appendLine("  Message: ${result.message}")
                if (result.cause != null) {
                    appendLine("  Cause: ${result.cause}")
                }
            }
        }

        appendLine("Instructions executed: ${result.instructionsExecuted}")
        appendLine("Final PC: ${result.finalPC ?: "unknown"}")
        appendLine("")

        // Final register state — use Language.registers for architecture-agnostic output.
        // This avoids hardcoding x86/ARM register names and supports any processor.
        appendLine("=== Final Register State ===")
        val allRegs = prog.language.registers
            .filter { !it.isHidden && it.parentRegister == null }  // top-level base registers only
            .sortedBy { it.name }
        if (allRegs.isEmpty()) {
            appendLine("  (no registers available)")
        } else {
            for (reg in allRegs) {
                try {
                    val bytes = thread.state.getVar(reg, PcodeExecutorStatePiece.Reason.INSPECT)
                    val value = bytesToLong(bytes)
                    val marker = when {
                        reg.isProgramCounter -> " (PC)"
                        reg.isProcessorContext -> " (CTX)"
                        else -> ""
                    }
                    appendLine("  ${reg.name.padEnd(10)} = 0x${value.toString(16).uppercase().padStart(reg.numBytes * 2, '0')}$marker")
                } catch (_: Exception) {
                    // Register not available in this state (e.g. not mapped in emulator)
                }
            }
        }
        appendLine("")

        // Memory writes are traced via the trace file (traceRW parameter),
        // not returned in the result output.

        // Warnings
        if (warnings.isNotEmpty()) {
            appendLine("=== Warnings (${warnings.size}) ===")
            for (w in warnings) {
                appendLine("  ⚠️ $w")
            }
            appendLine("")
        }
    }

    // ── Address / value parsing ────────────────────────────────────────

    private fun resolveAddress(
        prog: ghidra.program.model.listing.Program,
        str: String
    ): Address? {
        // Try as hex address
        try {
            return prog.addressFactory.getAddress(str)
        } catch (_: Exception) { }

        // Try as function name
        val fm = prog.functionManager
        val iter = fm.getFunctions(true)
        while (iter.hasNext()) {
            val f = iter.next()
            if (f.name.equals(str, ignoreCase = true)) {
                return f.entryPoint
            }
        }

        // Try as symbol — use getGlobalSymbols to avoid null Address parameter
        val syms = prog.symbolTable.getGlobalSymbols(str)
        if (syms.isNotEmpty()) {
            return syms[0].address
        }

        return null
    }

    private fun parseEndAddresses(json: String?): Set<Address> {
        if (json.isNullOrBlank()) return emptySet()
        val list = try {
            com.fasterxml.jackson.databind.ObjectMapper().readValue(json, List::class.java)
        } catch (e: Exception) {
            warnings.add("Failed to parse endAddresses JSON: ${e.message}")
            return emptySet()
        }
        val result = mutableSetOf<Address>()
        for (item in list) {
            val addr = resolveAddress(program!!, item.toString())
            if (addr != null) result.add(addr)
            else warnings.add("Cannot resolve end address: $item")
        }
        return result
    }

    private fun parseHexLong(str: String): Long? {
        return try {
            val clean = str.trim().removePrefix("0x").removePrefix("0X")
            java.lang.Long.parseUnsignedLong(clean, 16)
        } catch (_: Exception) {
            null
        }
    }

    // ── Byte/address conversion ────────────────────────────────────────

    private fun longToBytes(value: Long, size: Int): ByteArray {
        val result = ByteArray(size)
        var v = value
        for (i in 0 until size) {
            result[i] = (v and 0xFF).toByte()
            v = v shr 8
        }
        return result
    }

    private fun bytesToLong(bytes: ByteArray): Long {
        var result = 0L
        for (i in bytes.indices.reversed()) {
            result = (result shl 8) or (bytes[i].toLong() and 0xFF)
        }
        return result
    }

    private fun addressToBytes(addr: Address, size: Int): ByteArray {
        return longToBytes(addr.offset, size)
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray? {
        return try {
            val clean = hex.replace(" ", "").replace("0x", "")
            if (clean.length % 2 != 0) return null
            ByteArray(clean.length / 2) { i ->
                ((Character.digit(clean[i * 2], 16) shl 4) +
                 Character.digit(clean[i * 2 + 1], 16)).toByte()
            }
        } catch (_: Exception) {
            null
        }
    }
}
