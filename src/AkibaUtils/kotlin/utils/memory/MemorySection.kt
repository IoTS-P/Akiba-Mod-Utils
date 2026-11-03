package org.iotsplab.akiba.utils.memory

import ghidra.program.model.address.Address

/**
 * A memory-mapped region: file offset, size, permissions, name.
 * @param fileOffset Offset in the file (null when not backed by a file section).
 * @param size Size of the section.
 * @param mapStart Start address it is mapped to.
 * @param description Human-readable description.
 * @param name Section name.
 * @param prot Protection flags (a combination of read, write, execute).
 */
data class MemorySection(
    var fileOffset: Long?,
    var size: Long,
    var mapStart: Address,
    var description: String = "",
    var name: String = "",
    var prot: Int = PROT_WRITE or PROT_READ or PROT_EXEC,
) {
    override fun toString(): String {
        return """
            File offset: (${ fileOffset ?. let { "${it.toString(16)}~${(it + size).toString(16)}" } 
                                        ?: run { "Not mapped to any file section" }})
            Size: 0x${size.toString(16)}
            Map to: ${mapStart.addressSpace.name}:${mapStart.offset.toString(16)}~${(mapStart.offset + size).toString(16)}
            name: $name
            Description: $description
        """.trimIndent()
    }

    companion object {
        /**
         * 将内存段列表转换为格式化的字符串表示。
         *
         * @param sections 内存段列表。
         * @return 格式化后的内存段信息字符串。
         */
        fun sectionListString(sections: List<MemorySection>): String {
            return if (sections.isEmpty()) "Empty" else sections.sortedBy { it.mapStart } .mapIndexed { idx, s ->
                "Section #$idx:\n$s"
            }.joinToString("\n\n")
        }

        /**
         * 写保护标志。
         */
        const val PROT_WRITE = 0x1
        
        /**
         * 读保护标志。
         */
        const val PROT_READ = 0x2
        
        /**
         * 执行保护标志。
         */
        const val PROT_EXEC = 0x4
    }
}