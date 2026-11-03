@file:Suppress("DEPRECATION")
// Uses legacy `EmulatorHelper` API, deprecated in Ghidra 12.0 in favor of
// `ghidra.pcode.emu.PcodeEmulator`. See utils/emulator/Emulator.kt for the
// rationale for keeping the legacy API until the full migration is done.
package org.iotsplab.akiba.structure

import ghidra.app.emulator.EmulatorHelper
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.util.exception.NotFoundException

/**
 * 管理一组多项式表达式树并提供统一的计算接口。
 * 自动处理树的构建、合并和依赖解析。
 */
class PcodePolynomialTreeset {
    /**
     * 多项式表达式树的内部存储。
     */
    private val trees: MutableList<PcodePolynomialTree> = mutableListOf()

    /**
     * Adds a P-code op, building or updating the polynomial tree it belongs to.
     * Input varnodes with no tree get a fresh one; for the output varnode an
     * existing tree has its expressions replaced, otherwise a new tree merges the
     * dependency subtrees. Inputs are registered before the output tree is
     * resolved, which covers ops like `xxx INT_ADD xxx, yyy` where one varnode
     * appears on both sides.
     *
     * @param op the P-code op to add.
     * @throws IllegalArgumentException if the op cannot be handled.
     */
    @Throws(IllegalArgumentException::class)
    fun addPcode(op: PcodeOp) {
        op.inputs.forEach { input ->
            if (!input.isConstant && trees.none { it.output == input })
                trees.add(PcodePolynomialTree(input))
        }

        // Find if the tree representing this output varnode exists:
        // If so: remove all its expressions and replace it with this new one
        //      - NOTE: Need to handle the case like `xxx INT_ADD xxx, yyy`, a varnode cannot be both input and output
        // If not: add a new tree
        trees.indices.firstOrNull { idx -> trees[idx].output == op.output }
            ?.let { idx ->
                val newTree = PcodePolynomialTree(op)
                newTree.allVarnodeArguments().mapNotNull { varnode -> trees.find { it.output == varnode } }
                    .forEach { newTree.replace(it.output, it.root) }
                trees[idx] = newTree
            } ?:run {
                val newTree = PcodePolynomialTree(op)
                newTree.allVarnodeArguments().mapNotNull { varnode -> trees.find { it.output == varnode } }
                    .forEach { newTree.replace(it.output, it.root) }
                if (op.opcode == PcodeOp.COPY && !op.inputs[0].isConstant) {
                    newTree.root = trees.find { it.output == op.inputs[0] }?.root ?: run {
                        trees.add(PcodePolynomialTree(op.inputs[0]))
                        trees.last().root
                    }
                }
                trees.add(newTree)
            }
    }

    /**
     * 使用模拟器上下文计算目标 varnode 的值。
     *
     * @param context 提供内存和寄存器值的模拟器助手。
     * @param target 要计算的 varnode。
     * @return 包含计算值和大小的序对。
     * @throws NotFoundException 如果在任何树中都找不到目标 varnode 则抛出此异常。
     */
    @Throws(NotFoundException::class)
    fun calculate(context: EmulatorHelper, target: Varnode): Pair<Long, Int> {
        if (target.isAddress || target.isConstant)
            return Pair(target.address.offset, target.size)
        trees.find { it.output == target }?.let { tree -> return tree.calculate(context) }
            ?: throw NotFoundException("Target varnode not found")
    }
}