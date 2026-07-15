// @name: elf_plt_got_info
// @author: Akiba
// @description: Inspect ELF PLT/GOT related sections, relocation tables, dynamic table entries, and RELRO status.
// @parameters: maxRelocations (integer, optional) - maximum relocation entries to print per table, default 80; showDynamicSymbols (boolean, optional) - print dynamic function/object symbols, default false; maxSymbols (integer, optional) - maximum dynamic symbols to print, default 120

import org.iotsplab.akiba.script.AkibaScript
import org.iotsplab.akiba.utils.binFormat.ELFStructures
import ghidra.app.util.bin.format.elf.ElfDynamicType
import ghidra.app.util.bin.format.elf.ElfProgramHeaderConstants

class ElfPltGotInfo : AkibaScript() {
    override suspend fun execute() {
        val program = this.program ?: run { appendLine("Error: no program loaded"); return }
        if (!program.executableFormat.contains("ELF", ignoreCase = true)) {
            appendLine("Not an ELF program: executableFormat='${program.executableFormat}'")
            return
        }

        val elf = try { ELFStructures(program) }
            catch (e: Exception) { appendLine("Error: failed to parse ELF structures: ${e.message}"); return }
        val header = elf.elfHeader
        val maxRelocations = ((scriptArgs["maxRelocations"] as? Number)?.toInt() ?: 80).coerceAtLeast(1)
        val showDynamicSymbols = (scriptArgs["showDynamicSymbols"] as? Boolean) ?: false
        val maxSymbols = ((scriptArgs["maxSymbols"] as? Number)?.toInt() ?: 120).coerceAtLeast(1)

        appendLine("=== ELF PLT/GOT Information ===")
        appendLine("Program: ${program.name}")
        appendLine("Entry: 0x${header.e_entry().toString(16)}")
        appendLine("Endian: ${if (header.isLittleEndian) "little" else "big"}")
        appendLine("")

        val hasRelroSegment = elf.elfProgramHeaders.any { it.getType() == ElfProgramHeaderConstants.PT_GNU_RELRO }
        val bindNow = hasBindNow(header)
        val relro = when {
            hasRelroSegment && bindNow -> "Full RELRO (PT_GNU_RELRO + BIND_NOW)"
            hasRelroSegment -> "Partial RELRO (PT_GNU_RELRO without BIND_NOW)"
            else -> "No RELRO (PT_GNU_RELRO not found)"
        }
        appendLine("=== RELRO ===")
        appendLine("$relro")
        appendLine("")

        appendLine("=== Program Headers Relevant to RELRO/GOT ===")
        var phCount = 0
        for (ph in elf.elfProgramHeaders) {
            if (ph.getType() == ElfProgramHeaderConstants.PT_GNU_RELRO || ph.getType() == ElfProgramHeaderConstants.PT_DYNAMIC) {
                appendLine(String.format("  type=%s vaddr=0x%x memSize=0x%x fileSize=0x%x flags=%s",
                    phTypeName(ph.getType()), ph.getVirtualAddress(), ph.getMemorySize(), ph.getFileSize(), phPerms(ph)))
                phCount++
            }
        }
        if (phCount == 0) appendLine("  (none)")
        appendLine("")

        appendLine("=== Dynamic Table PLT/GOT Entries ===")
        val dyn = try { header.getDynamicTable() } catch (_: Exception) { null }
        if (dyn == null) {
            appendLine("  (no dynamic table)")
        } else {
            printDynValue("DT_PLTGOT", dyn, ElfDynamicType.DT_PLTGOT)
            printDynValue("DT_JMPREL", dyn, ElfDynamicType.DT_JMPREL)
            printDynValue("DT_BIND_NOW", dyn, ElfDynamicType.DT_BIND_NOW)
            printDynValue("DT_FLAGS", dyn, ElfDynamicType.DT_FLAGS)
            printDynValue("DT_FLAGS_1", dyn, ElfDynamicType.DT_FLAGS_1)
        }
        appendLine("")

        appendLine("=== PLT/GOT Sections ===")
        val interestingSections = elf.elfSectionHeaders.entries
            .filter { (name, _) -> name.contains("plt", ignoreCase = true) || name.contains("got", ignoreCase = true) }
            .sortedBy { it.value.getAddress() }
        if (interestingSections.isEmpty()) appendLine("  (no .plt/.got-like ELF sections found)")
        for ((name, sh) in interestingSections) {
            val block = program.memory.getBlock(program.addressFactory.defaultAddressSpace.getAddress(sh.getAddress()))
            appendLine(String.format("  %-18s addr=0x%x size=0x%x type=0x%x flags=0x%x loaded=%s block=%s",
                name.ifBlank { "<unnamed>" }, sh.getAddress(), sh.getSize(), sh.getType(), sh.getFlags(), sh.isAlloc(), block?.name ?: "-"))
        }
        appendLine("")

        appendLine("=== Relocation Tables Related to PLT/GOT ===")
        val dynSyms = try { header.getDynamicSymbolTable()?.getSymbols() } catch (_: Exception) { null }
        val relocTables = try { header.getRelocationTables() } catch (_: Exception) { emptyArray() }
        var tableCount = 0
        for (rt in relocTables) {
            val targetSection = try { rt.getSectionToBeRelocated()?.getNameAsString() ?: "?" } catch (_: Exception) { "?" }
            val looksRelevant = targetSection.contains("plt", true) || targetSection.contains("got", true) ||
                rt.getFileOffset() != 0L
            if (!looksRelevant) continue
            tableCount++
            appendLine("-- relocation table #$tableCount target=$targetSection fileOffset=0x${rt.getFileOffset().toString(16)} count=${rt.getRelocationCount()} --")
            var shown = 0
            for (rel in rt.getRelocations()) {
                if (shown >= maxRelocations) break
                val sym = dynSyms?.getOrNull(rel.getSymbolIndex())
                val symName = try { sym?.getNameAsString() } catch (_: Exception) { null }
                appendLine(String.format("  offset=0x%x type=%d symIndex=%d symbol=%s addend=%s",
                    rel.getOffset(), rel.getType(), rel.getSymbolIndex(), symName ?: "-",
                    if (rel.hasAddend()) "0x${rel.getAddend().toString(16)}" else "<implicit>"))
                shown++
            }
            if (rt.getRelocationCount() > maxRelocations) appendLine("  ... truncated; increase maxRelocations to show more")
        }
        if (tableCount == 0) appendLine("  (no relevant relocation tables found)")

        if (showDynamicSymbols) {
            appendLine("")
            appendLine("=== Dynamic Symbols (truncated) ===")
            val syms = dynSyms
            if (syms == null) appendLine("  (no dynamic symbol table)")
            else syms.take(maxSymbols).forEachIndexed { idx, sym ->
                val name = try { sym.getNameAsString() } catch (_: Exception) { "?" }
                appendLine(String.format("  [%4d] value=0x%x size=0x%x type=%d name=%s", idx, sym.getValue(), sym.getSize(), sym.getType(), name))
            }
            if (syms != null && syms.size > maxSymbols) appendLine("  ... truncated; increase maxSymbols to show more")
        }
    }

    private fun hasBindNow(header: ghidra.app.util.bin.format.elf.ElfHeader): Boolean {
        val dyn = try { header.getDynamicTable() } catch (_: Exception) { null } ?: return false
        if (dyn.containsDynamicValue(ElfDynamicType.DT_BIND_NOW)) return true
        val flags = try { if (dyn.containsDynamicValue(ElfDynamicType.DT_FLAGS)) dyn.getDynamicValue(ElfDynamicType.DT_FLAGS) else 0L } catch (_: Exception) { 0L }
        val flags1 = try { if (dyn.containsDynamicValue(ElfDynamicType.DT_FLAGS_1)) dyn.getDynamicValue(ElfDynamicType.DT_FLAGS_1) else 0L } catch (_: Exception) { 0L }
        return (flags and ElfDynamicType.DF_BIND_NOW.toLong()) != 0L || (flags1 and ElfDynamicType.DF_1_NOW.toLong()) != 0L
    }

    private fun printDynValue(name: String, dyn: ghidra.app.util.bin.format.elf.ElfDynamicTable, type: ghidra.app.util.bin.format.elf.ElfDynamicType) {
        if (dyn.containsDynamicValue(type)) appendLine("  $name = 0x${dyn.getDynamicValue(type).toString(16)}")
        else appendLine("  $name = <absent>")
    }

    private fun phTypeName(type: Int): String = when (type) {
        ElfProgramHeaderConstants.PT_DYNAMIC -> "PT_DYNAMIC"
        ElfProgramHeaderConstants.PT_GNU_RELRO -> "PT_GNU_RELRO"
        else -> "0x${type.toString(16)}"
    }

    private fun phPerms(ph: ghidra.app.util.bin.format.elf.ElfProgramHeader): String {
        return "" + (if (ph.isRead()) "r" else "-") + (if ((ph.getFlags() and ElfProgramHeaderConstants.PF_W) != 0) "w" else "-") + (if (ph.isExecute()) "x" else "-")
    }
}
