package org.iotsplab.akiba.utils.highFunction

import ghidra.app.decompiler.ClangTokenGroup
import ghidra.app.decompiler.DecompileResults
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeBlockBasic
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TimeoutTaskMonitor
import java.util.concurrent.TimeUnit

/**
 * 获取高级函数的直接前驱映射。
 * 为每个基本块构建其直接前驱块的集合。
 *
 * @return 映射表，键为基本块，值为其直接前驱块的集合。
 */
fun HighFunction.getDirectAncestorMap(): Map<PcodeBlockBasic, Set<PcodeBlockBasic>> {
    val result: MutableMap<PcodeBlockBasic, MutableSet<PcodeBlockBasic>> = mutableMapOf()
    basicBlocks.forEach { b ->
        // 可能存在没有输出的块，例如返回块
        if (b.trueOut != null)
            result[b.trueOut] ?.add(b) ?: run { result[b.trueOut as PcodeBlockBasic] = mutableSetOf(b) }
        if (b.falseOut != null)
            result[b.falseOut] ?.add(b) ?: run { result[b.falseOut as PcodeBlockBasic] = mutableSetOf(b) }
    }
    return result.mapValues { it.value.toSet() }
}

/**
 * 获取可以到达目标基本块的所有基本块。
 * 通过前驱映射反向搜索所有能够到达目标块的块。
 *
 * @param target 目标基本块。
 * @return 可以到达目标的基本块集合。
 * @throws IllegalArgumentException 如果无法构建前驱映射。
 */
@Throws(IllegalArgumentException::class)
fun HighFunction.getBlocksReachableTo(target: PcodeBlockBasic): Set<PcodeBlockBasic> {
    val ancestorMap = getDirectAncestorMap()
    var result: MutableSet<PcodeBlockBasic> = mutableSetOf()
    val nextRoundResult: MutableSet<PcodeBlockBasic> = ancestorMap[target] ?.toMutableSet() ?: return setOf()

    while (result.size != nextRoundResult.size) {
        result = nextRoundResult.toMutableSet()
        nextRoundResult.clear()
        result.forEach { nextRoundResult.addAll(ancestorMap[it] ?: setOf()) }
    }

    return result
}

/**
 * 获取包含指定地址的基本块。
 * 注意：某些特殊的基本块可能不占用完整的指令，例如 x86 架构中的 cmovxx 条件移动指令会创建一个迷你基本块，
 * 但这种基本块对其他块没有影响，所以我们忽略它。
 *
 * @param addr 要查找的地址。
 * @return 包含该地址的基本块，如果不存在则返回 null。
 */
fun HighFunction.getBlockAt(addr: Address): PcodeBlockBasic? {
    // 可能存在一些特殊的基本块，甚至无法占用单条指令
    // 例如 x86 架构中的 cmovxx，这是一个条件移动指令，会在该指令中创建一个迷你基本块
    // 但这个迷你基本块对其他块没有任何影响，所以我们简单地忽略它
    return basicBlocks.firstOrNull { it.start == addr && it.start != it.stop }
}

/**
 * 获取以指定地址结束的基本块。
 * 与 getBlockAt 相同，忽略特殊的小型基本块。
 *
 * @param addr 要查找的地址。
 * @return 以该地址结束的基本块，如果不存在则返回 null。
 */
fun HighFunction.getBlockEndsWith(addr: Address): PcodeBlockBasic? {
    // Same as getBlockAt
    return basicBlocks.firstOrNull { it.stop == addr && it.start != it.stop }
}

/**
 * 获取函数的默认反编译结果。
 *
 * @param timeoutSeconds 反编译超时时间（秒）。默认 120 秒，足以处理
 *   10000+ 条指令的大型函数。之前的默认值 11 秒对于超大函数会静默失败
 *   （反编译不抛异常，但 [DecompileResults.decompileCompleted] 返回 false，
 *   导致后续获取 C 代码时得到空结果或 NPE）。Ghidra GUI 的反编译器通常
 *   不设硬超时，因此 GUI 中等待数秒后仍能成功。
 * @return 反编译结果对象。
 * @throws IllegalStateException 如果反编译未在超时时间内完成（超时）。
 * @throws IllegalArgumentException 如果反编译过程中发生错误。
 */
@Throws(IllegalArgumentException::class, IllegalStateException::class)
fun Function.getDefaultDecompResult(timeoutSeconds: Int = 120): DecompileResults {
    val decompiler = HighFunctionUtil.getDefaultDecompiler(program)
    // monitor 超时比 decompileFunction 的 timeout 多 2 秒，确保
    // decompileFunction 的超时逻辑先触发（返回更精确的 errorMessage），
    // 而不是 monitor 强制取消导致结果不完整。
    val monitor = TimeoutTaskMonitor.timeoutIn((timeoutSeconds + 2).toLong(), TimeUnit.SECONDS)
    val result = decompiler.decompileFunction(this, timeoutSeconds, monitor)
    decompiler.closeProgram()
    if (!result.decompileCompleted()) {
        val msg = result.errorMessage ?: "decompilation did not complete within ${timeoutSeconds}s"
        throw IllegalStateException("Decompilation failed for ${this.name} @ ${this.entryPoint}: $msg")
    }
    return result
}

/**
 * 获取函数的 C 代码结构。
 * 返回反编译后的 C 代码标记组，包含完整的语法树信息。
 *
 * @param timeoutSeconds 反编译超时时间（秒），默认 120。
 * @return C 代码标记组对象。
 */
fun Function.getCCodeStructure(timeoutSeconds: Int = 120): ClangTokenGroup {
    return getDefaultDecompResult(timeoutSeconds).cCodeMarkup
}

/**
 * 获取函数的 C 代码字符串表示。
 * 返回反编译后的格式化 C 代码文本。
 *
 * @param timeoutSeconds 反编译超时时间（秒），默认 120。
 * @return C 代码字符串。
 */
fun Function.getCCode(timeoutSeconds: Int = 120): String {
    return getDefaultDecompResult(timeoutSeconds).decompiledFunction.c
}