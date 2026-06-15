// @name: change_variable_type
// @author: Akiba
// @description: Change the data type of a local variable or parameter within a function. Identify the variable by its name (e.g. "param_1", "local_4") or stack offset.
// @parameters: target (string) - Function name or hex address; variable (string) - Variable name (e.g. "param_1", "local_8") or stack offset (e.g. "-0x4"); type (string) - Target data type name (e.g. "int", "char*", "DWORD")

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.data.*
import ghidra.program.model.symbol.SourceType

class ChangeVariableType : AkibaScript() {
    override suspend fun execute() {
        val program = currentProgram ?: run { appendLine("Error: no program loaded"); return }
        val target = scriptArgs["target"] as? String
            ?: run { appendLine("Error: 'target' parameter required"); return }
        val varName = scriptArgs["variable"] as? String
            ?: run { appendLine("Error: 'variable' parameter required"); return }
        val typeName = scriptArgs["type"] as? String
            ?: run { appendLine("Error: 'type' parameter required"); return }

        val func = resolveFunction(program, target)
        if (func == null) { appendLine("Error: function '$target' not found"); return }

        val dtm = program.dataTypeManager
        val newType = resolveDataType(dtm, typeName)
        if (newType == null) { appendLine("Error: data type '$typeName' not found"); return }

        val variable = findVariable(func, varName)
        if (variable == null) { appendLine("Error: variable '$varName' not found in function '${func.name}'"); return }

        val txId = program.startTransaction("change_variable_type")
        var ok = false
        try {
            val oldTypeName = variable.dataType.name
            variable.setDataType(newType, SourceType.USER_DEFINED)
            ok = true
            appendLine("Changed '${variable.name}' type: $oldTypeName -> ${newType.name}")
            appendLine("In function '${func.name}' @ ${func.entryPoint}")
        } catch (e: Exception) {
            appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, ok)
        }
    }

    private fun resolveFunction(program: ghidra.program.model.listing.Program, target: String): ghidra.program.model.listing.Function? {
        val fm = program.functionManager
        val iter = fm.getFunctions(true)
        while (iter.hasNext()) { val f = iter.next(); if (f.name.equals(target, true)) return f }
        return try { val a = program.addressFactory.getAddress(target); fm.getFunctionAt(a) ?: fm.getFunctionContaining(a) }
        catch (_: Exception) { null }
    }

    private fun resolveDataType(dtm: DataTypeManager, name: String): DataType? {
        return dtm.getDataType(CategoryPath.ROOT, name)
    }

    private fun findVariable(func: ghidra.program.model.listing.Function, name: String): ghidra.program.model.listing.Variable? {
        for (v in func.allVariables) {
            if (v.name.equals(name, ignoreCase = true)) return v
        }
        return null
    }
}
