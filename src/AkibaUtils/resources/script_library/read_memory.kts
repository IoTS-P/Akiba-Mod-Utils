// @name: read_memory
// @author: Akiba
// @description: Read a memory region from the current program and render it as bytes, characters, or integer values.
// @parameters: address (string) - start address, e.g. "0x401000"; size (integer) - number of bytes to read; format (string, optional) - bytes, ascii, utf8, u8, u16, u32, u64, i8, i16, i32, i64, pointer (default: bytes); endian (string, optional) - little, big, or program (default: program); columns (integer, optional) - bytes per row for byte/char output, default 16; maxItems (integer, optional) - maximum integer items to print, default 256

import org.iotsplab.akiba.script.AkibaScript
import java.nio.charset.Charset

class ReadMemory : AkibaScript() {
    override suspend fun execute() {
        val startText = scriptArgs["address"] as? String
            ?: run { appendLine("Error: 'address' parameter is required"); return }
        val size = (scriptArgs["size"] as? Number)?.toInt()
            ?: run { appendLine("Error: 'size' parameter is required"); return }
        if (size <= 0) { appendLine("Error: 'size' must be positive"); return }
        if (size > 1024 * 1024) { appendLine("Error: refusing to read more than 1 MiB at once"); return }

        val format = ((scriptArgs["format"] as? String) ?: "bytes").lowercase()
        val columns = ((scriptArgs["columns"] as? Number)?.toInt() ?: 16).coerceIn(1, 64)
        val maxItems = ((scriptArgs["maxItems"] as? Number)?.toInt() ?: 256).coerceAtLeast(1)
        val bigEndian = when (((scriptArgs["endian"] as? String) ?: "program").lowercase()) {
            "big", "be" -> true
            "little", "le" -> false
            else -> program.language.isBigEndian
        }

        val start = try { program.addressFactory.getAddress(startText) }
            catch (_: Exception) { null }
        if (start == null) {
            appendLine("Error: invalid address '$startText'")
            return
        }

        val block = program.memory.getBlock(start)
        if (block == null) {
            appendLine("Error: address $start is not inside any memory block")
            return
        }
        val end = try { start.add(size.toLong() - 1) } catch (_: Exception) { null }
        if (end == null || !block.contains(end)) {
            appendLine("Error: requested range $start + $size bytes crosses block boundary")
            appendLine("Containing block: ${block.name} ${block.start}-${block.end} (${block.size} bytes)")
            return
        }

        val bytes = ByteArray(size)
        try { program.memory.getBytes(start, bytes) }
        catch (e: Exception) { appendLine("Error reading memory: ${e.message}"); return }

        appendLine("=== Memory Region ===")
        appendLine("Address: $start - $end")
        appendLine("Size: $size bytes")
        appendLine("Block: ${block.name} (${perms(block)}) loaded=${block.isLoaded} initialized=${block.isInitialized}")
        appendLine("Format: $format endian=${if (bigEndian) "big" else "little"}")
        appendLine("")

        when (format) {
            "bytes", "hex" -> dumpBytes(start, bytes, columns)
            "ascii", "chars" -> dumpChars(start, bytes, columns, Charset.forName("ISO-8859-1"))
            "utf8", "string" -> appendLine(String(bytes, Charset.forName("UTF-8")))
            "u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "pointer" -> dumpIntegers(start, bytes, format, bigEndian, maxItems)
            else -> appendLine("Error: unsupported format '$format'")
        }
    }

    private fun dumpBytes(start: ghidra.program.model.address.Address, bytes: ByteArray, columns: Int) {
        var offset = 0
        while (offset < bytes.size) {
            val row = bytes.sliceArray(offset until minOf(offset + columns, bytes.size))
            appendLine("${start.add(offset.toLong())}: " + row.joinToString(" ") { "%02x".format(it.toInt() and 0xff) })
            offset += columns
        }
    }

    private fun dumpChars(start: ghidra.program.model.address.Address, bytes: ByteArray, columns: Int, charset: Charset) {
        var offset = 0
        while (offset < bytes.size) {
            val row = bytes.sliceArray(offset until minOf(offset + columns, bytes.size))
            val text = String(row, charset).map { ch -> if (ch.code in 32..126) ch else '.' }.joinToString("")
            val hex = row.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }.padEnd(columns * 3)
            appendLine("${start.add(offset.toLong())}: $hex |$text|")
            offset += columns
        }
    }

    private fun dumpIntegers(start: ghidra.program.model.address.Address, bytes: ByteArray, format: String, bigEndian: Boolean, maxItems: Int) {
        val unit = when (format) {
            "u8", "i8" -> 1
            "u16", "i16" -> 2
            "u32", "i32" -> 4
            "u64", "i64" -> 8
            "pointer" -> program!!.defaultPointerSize
            else -> 1
        }
        val signed = format.startsWith("i")
        val count = minOf(bytes.size / unit, maxItems)
        for (i in 0 until count) {
            val off = i * unit
            val raw = bytes.sliceArray(off until off + unit)
            val unsigned = toUnsignedLong(raw, bigEndian)
            val valueText = if (signed) toSignedString(unsigned, unit) else unsigned.toString()
            val hexText = raw.joinToString("") { "%02x".format(it.toInt() and 0xff) }
            appendLine("${start.add(off.toLong())}: 0x$hexText  $valueText")
        }
        if (bytes.size / unit > maxItems) appendLine("... truncated: pass a larger maxItems to show more")
        val rem = bytes.size % unit
        if (rem != 0) appendLine("Note: $rem trailing byte(s) not shown because they do not form a complete $unit-byte item")
    }

    private fun toUnsignedLong(bytes: ByteArray, bigEndian: Boolean): Long {
        var v = 0L
        val ordered = if (bigEndian) bytes.toList() else bytes.reversed()
        for (b in ordered) v = (v shl 8) or (b.toLong() and 0xffL)
        return v
    }

    private fun toSignedString(value: Long, size: Int): String {
        return when (size) {
            1 -> value.toByte().toString()
            2 -> value.toShort().toString()
            4 -> value.toInt().toString()
            else -> value.toString()
        }
    }

    private fun perms(block: ghidra.program.model.mem.MemoryBlock): String {
        return "" + (if (block.isRead) "r" else "-") + (if (block.isWrite) "w" else "-") + (if (block.isExecute) "x" else "-")
    }
}
