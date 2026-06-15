package org.iotsplab.akiba.utils.binFormat

import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.bin.format.elf.ElfHeader
import ghidra.app.util.bin.format.elf.ElfProgramHeader
import ghidra.app.util.bin.format.elf.ElfProgramHeaderConstants
import ghidra.app.util.bin.format.elf.ElfSectionHeader
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants
import ghidra.app.util.bin.format.elf.ElfSectionHeaderType
import ghidra.features.base.memsearch.bytesource.AddressableByteSource
import ghidra.features.base.memsearch.bytesource.ProgramByteSource
import ghidra.features.base.memsearch.format.SearchFormat
import ghidra.features.base.memsearch.gui.SearchSettings
import ghidra.features.base.memsearch.matcher.RegExByteMatcher
import ghidra.features.base.memsearch.matcher.SearchData
import ghidra.features.base.memsearch.searcher.MemoryMatch
import ghidra.features.base.memsearch.searcher.MemorySearcher
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.datastruct.ListAccumulator
import ghidra.util.task.TaskMonitor
import org.apache.logging.log4j.Logger
import org.iotsplab.akiba.utils.memory.MemoryUtil
import org.iotsplab.akiba.utils.string.RegexSearcher.Companion.REGEX_MAX_SEARCH_COUNT
import java.nio.charset.StandardCharsets

/**
 * ELF 文件格式结构解析类。
 * 用于解析和访问 ELF 文件的头部信息、程序头表和节头表。
 *
 * @param program Ghidra 程序对象。
 * @param logger 可选的日志记录器，用于记录解析过程中的错误。
 */
class ELFStructures (
    private val program: Program,
    private val logger: Logger? = null
) {
    /**
     * ELF 文件头。
     * 包含 ELF 文件的基本信息和元数据。
     */
    lateinit var elfHeader: ElfHeader
    
    /**
     * ELF 程序头表列表。
     * 描述进程映像的各个段，用于加载和执行。
     */
    lateinit var elfProgramHeaders: List<ElfProgramHeader>
    
    /**
     * ELF 节头表映射。
     * 键为节区名称，值为节头对象，描述各个节区的信息。
     */
    lateinit var elfSectionHeaders: Map<String, ElfSectionHeader>

    init {
        val blockNames = program.memory.blocks.map { it.name }.toSet()
        val hasStandardBlocks = blockNames.containsAll(
            listOf("_elfHeader", "_elfProgramHeaders", "_elfSectionHeaders", ".shstrtab"))

        if (hasStandardBlocks) {
            // Primary path: Ghidra imported with the ELF loader, named blocks exist.
            parseFromStandardBlocks()
        } else {
            // Fallback path: ELF binary was imported via a non-ELF loader
            // (e.g. Raw Binary). Read structures from program memory directly.
            val base = program.imageBase
            val magic = ByteArray(4)
            try { program.memory.getBytes(base, magic) } catch (_: Exception) { }
            if (!magic.contentEquals(ELF_MAGIC))
                throw IllegalArgumentException("Program doesn't contain an ELF file")

            parseFromRawMemory(base)
        }
    }

    /** Parse ELF structures when Ghidra's ELF-imported named blocks exist. */
    private fun parseFromStandardBlocks() {
        val hBlock = program.memory.getBlock("_elfHeader")
        val hbContents = ByteArray(hBlock.size.toInt())
        hBlock.getBytes(hBlock.start, hbContents)
        val elfHeaderBp = ByteArrayProvider(hbContents)
        elfHeader = ElfHeader(elfHeaderBp) { err -> logger?.error(err) }

        val phBlock = program.memory.getBlock("_elfProgramHeaders")
        val phbContents = ByteArray(ELF_PROGRAM_HEADER_ENTRY_SIZE)
        val programHeaders = mutableListOf<ElfProgramHeader>()
        (0..<phBlock.size / ELF_PROGRAM_HEADER_ENTRY_SIZE).forEach { idx ->
            phBlock.getBytes(phBlock.start.add(idx * ELF_PROGRAM_HEADER_ENTRY_SIZE), phbContents)
            val bp = ByteArrayProvider(phbContents)
            val reader = BinaryReader(bp, elfHeader.isLittleEndian)
            programHeaders.add(ElfProgramHeader(reader, elfHeader))
        }
        elfProgramHeaders = programHeaders

        val shBlock = program.memory.getBlock("_elfSectionHeaders")
        val shbContents = ByteArray(ELF_SECTION_HEADER_ENTRY_SIZE)
        val sectionHeaders = mutableListOf<ElfSectionHeader>()
        val shstrtabBlock = program.memory.getBlock(".shstrtab")
        val shstrtabContents = ByteArray(shBlock.size.toInt())
        shstrtabBlock.getBytes(shstrtabBlock.start, shstrtabContents)
        val sectionHeaderNames = mutableListOf<String>()
        (0..<shBlock.size / ELF_SECTION_HEADER_ENTRY_SIZE).forEach { idx ->
            shBlock.getBytes(shBlock.start.add(idx * ELF_SECTION_HEADER_ENTRY_SIZE), shbContents)
            val bp = ByteArrayProvider(shbContents)
            val reader = BinaryReader(bp, elfHeader.isLittleEndian)
            val sh = ElfSectionHeader(reader, elfHeader)
            sectionHeaders.add(sh)
            sectionHeaderNames.add(
                if (sh.type == ElfSectionHeaderType.SHT_NULL.value) ""
                else {
                    val length = (0..<shstrtabContents.size).filter {
                        shstrtabContents[it] == 0.toByte() && it > sh.name
                    }.min() - sh.name
                    String(shstrtabContents, sh.name, length)
                }
            )
        }
        elfSectionHeaders = sectionHeaderNames.zip(sectionHeaders).toMap()
    }

    /**
     * Parse ELF structures directly from program memory.
     * Used when Ghidra imported the binary without creating the standard
     * _elfHeader / _elfProgramHeaders / _elfSectionHeaders blocks.
     *
     * All file offsets in the ELF header are relative to the program's
     * image base (which is 0x0 for Raw Binary imports).
     */
    private fun parseFromRawMemory(base: ghidra.program.model.address.Address) {
        // ── Read and parse the ELF header ──────────────────────────────
        val hdrSize = 64  // e_ident(16) + fixed fields; ElfHeader parser reads exactly this
        val hdrBytes = ByteArray(hdrSize)
        program.memory.getBytes(base, hdrBytes)
        elfHeader = ElfHeader(ByteArrayProvider(hdrBytes)) { err -> logger?.error(err) }

        val isLE = elfHeader.isLittleEndian

        // ── Read program headers ───────────────────────────────────────
        val phoff = elfHeader.e_phoff()
        val phentsize = elfHeader.e_phentsize().toInt()
        val phnum = elfHeader.programHeaderCount
        val phEntryBytes = ByteArray(phentsize)
        val programHeaders = mutableListOf<ElfProgramHeader>()
        for (i in 0 until phnum) {
            val addr = base.add(phoff + i.toLong() * phentsize)
            program.memory.getBytes(addr, phEntryBytes)
            val reader = BinaryReader(ByteArrayProvider(phEntryBytes), isLE)
            programHeaders.add(ElfProgramHeader(reader, elfHeader))
        }
        elfProgramHeaders = programHeaders

        // ── Read section headers ───────────────────────────────────────
        val shoff = elfHeader.e_shoff()
        val shentsize = elfHeader.e_shentsize().toInt()
        val shnum = elfHeader.sectionHeaderCount
        val shEntryBytes = ByteArray(shentsize)
        val sectionHeaders = mutableListOf<ElfSectionHeader>()
        for (i in 0 until shnum) {
            val addr = base.add(shoff + i.toLong() * shentsize)
            program.memory.getBytes(addr, shEntryBytes)
            val reader = BinaryReader(ByteArrayProvider(shEntryBytes), isLE)
            sectionHeaders.add(ElfSectionHeader(reader, elfHeader))
        }

        // ── Read .shstrtab to resolve section names ────────────────────
        val shstrndx = elfHeader.e_shstrndx()
        val shstrSec = sectionHeaders.getOrNull(shstrndx)
        val sectionHeaderNames: List<String>
        if (shstrSec != null) {
            val shstrSize = shstrSec.size.toInt()
            val shstrBytes = ByteArray(shstrSize)
            val shstrAddr = base.add(shstrSec.offset)
            program.memory.getBytes(shstrAddr, shstrBytes)
            sectionHeaderNames = sectionHeaders.map { sh ->
                if (sh.type == ElfSectionHeaderType.SHT_NULL.value || sh.name >= shstrSize) ""
                else {
                    val end = (sh.name until shstrSize).first { shstrBytes[it] == 0.toByte() }
                    String(shstrBytes, sh.name, end - sh.name)
                }
            }
        } else {
            sectionHeaderNames = sectionHeaders.map { "" }
        }
        elfSectionHeaders = sectionHeaderNames.zip(sectionHeaders).toMap()
    }

    /**
     * 获取节区所属的程序头。
     * 查找包含指定节区的程序头表项。
     *
     * @param section 要查询的 ELF 节头。
     * @return 包含该节区的程序头，如果不存在则返回 null。
     */
    fun getBelongedProgram(section: ElfSectionHeader): ElfProgramHeader? {
        return elfProgramHeaders.firstOrNull { phdr ->
            phdr.virtualAddress <= section.address && section.address < phdr.virtualAddress + phdr.memorySize
        }
    }

    /**
     * 判断节区是否为调试节区。
     * 调试节区不属于任何程序头，仅用于调试信息。
     *
     * @param section 要检查的 ELF 节头。
     * @return 如果是调试节区则返回 true，否则返回 false。
     */
    fun isDebugSection(section: ElfSectionHeader): Boolean {
        return elfProgramHeaders.none { phdr ->
            phdr.virtualAddress <= section.address && section.address < phdr.virtualAddress + phdr.memorySize
        }
    }

    /**
     * 获取节区的实际权限。
     * 根据节区所属的程序头和节区标志计算实际权限，并修正写权限和执行权限。
     *
     * @param section 要查询的 ELF 节头。
     * @return 节区的实际权限值（读、写、执行的组合）。
     * @throws IllegalStateException 如果节区不属于任何程序头。
     */
    fun getRealSectionPermission(section: ElfSectionHeader): Int {
        val phdrEntry = getBelongedProgram(section)!!
        var perm = phdrEntry.flags and ELF_PHDR_PF_ALL
        // 修正写权限
        if ((section.flags and ElfSectionHeaderConstants.SHF_WRITE.toLong()) == 0L)
            perm = perm and (ElfProgramHeaderConstants.PF_X or ElfProgramHeaderConstants.PF_R)
        // 修正执行权限
        if ((section.flags and ElfSectionHeaderConstants.SHF_EXECINSTR.toLong()) == 0L)
            perm = perm and (ElfProgramHeaderConstants.PF_R or ElfProgramHeaderConstants.PF_W)
        return perm
    }

    /**
     * 获取 ARM Cortex-M 固件文件中断向量表的首地址。
     * 通过在需要加载的段中搜索入口地址值来判断中断向量表的位置，因为中断向量表的第 4-7 字节即应为固件入口地址。
     *
     * @return 寻找到的中断向量表首地址
     * @throws IllegalStateException 没有在需要加载的段中找到入口地址，或找到多个入口地址
     */
    @Throws(IllegalStateException::class)
    fun getIvtTableStart(): Address {
        val entryPoint = program.addressFactory.defaultAddressSpace.getAddress(elfHeader.e_entry())
        val byteSource: AddressableByteSource = ProgramByteSource(program)

        val target = String(MemoryUtil.numberToBytes(entryPoint.offset).sliceArray(0..3),
            StandardCharsets.ISO_8859_1)
            .replace("\\", "\\\\")
            .replace("(", "\\(").replace(")", "\\)")
            .replace("[", "\\[").replace("]", "\\]")
            .replace("{", "\\{").replace("}", "\\}")
            .replace("+", "\\+")
            .replace("*", "\\*")
            .replace("?", "\\?")
            .replace(".", "\\.")
        val searcher = MemorySearcher(byteSource,
            RegExByteMatcher(
                target, SearchSettings().withSearchFormat(SearchFormat.BINARY)),
            program.memory.allInitializedAddressSet, REGEX_MAX_SEARCH_COUNT)
        val results = ListAccumulator<MemoryMatch<SearchData>>()
        searcher.findAll(results, TaskMonitor.DUMMY)
        val resultList = results.asList().filter {
            it.address.addressSpace == program.addressFactory.defaultAddressSpace }
        when (resultList.size) {
            0 -> throw IllegalStateException("Nowhere found to refer entry point")
            1 -> return resultList[0].address.subtract(4)
            // TODO: How to choose from multiple matches?
            else -> throw IllegalStateException("Multiple reference found to entry point")
        }
    }

    companion object {
        /** ELF magic bytes: 0x7f 'E' 'L' 'F' */
        private val ELF_MAGIC = byteArrayOf(0x7f, 0x45, 0x4c, 0x46)

        /**
         * ELF 程序头表项大小
         */
        const val ELF_PROGRAM_HEADER_ENTRY_SIZE = 0x20

        /**
         * ELF 节头表项大小
         */
        const val ELF_SECTION_HEADER_ENTRY_SIZE = 0x28

        /**
         * ELF 段权限位掩码
         */
        const val ELF_PHDR_PF_ALL = 7

        /**
         * 将 ELF 段的权限转换为字符串。
         *
         * @param perm ELF 段权限整数值
         * @return ELF 段权限字符串
         * @throws IllegalStateException 没有在需要加载的段中找到入口地址，或找到多个入口地址
         */
        fun getPermissionString(perm: Int): String {
            var ret = ""
            ret += if (perm and ElfProgramHeaderConstants.PF_R != 0) "r" else "-"
            ret += if (perm and ElfProgramHeaderConstants.PF_W != 0) "w" else "-"
            ret += if (perm and ElfProgramHeaderConstants.PF_X != 0) "x" else "-"
            return ret
        }
    }
}
