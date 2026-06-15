// @name: create_data_type
// @author: Akiba
// @description: Create a new structure or union data type in the program's data type manager. Optionally add named components with specified types.
// @parameters: name (string) - Name for the new data type; kind (string, optional) - "structure" or "union" (default: "structure"); category (string, optional) - Category path, e.g. "/myTypes" (default: "/"); components (string, optional) - JSON array of component objects: [{"name":"field1","type":"int","size":4}, {"name":"field2","type":"char*"}]. 'type' is the type name; 'size' is optional (only for non-pointer types when you want a specific byte length). If 'type' is omitted, the component will use 'undefined' with the given size.

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.data.*

class CreateDataType : AkibaScript() {
    override suspend fun execute() {
        val program = currentProgram ?: run { appendLine("Error: no program loaded"); return }
        val name = scriptArgs["name"] as? String
            ?: run { appendLine("Error: 'name' parameter required"); return }
        val kind = (scriptArgs["kind"] as? String)?.lowercase() ?: "structure"
        val categoryStr = (scriptArgs["category"] as? String) ?: "/"
        val dtm = program.dataTypeManager

        val txId = program.startTransaction("create_data_type")
        var ok = false
        try {
            val catPath = CategoryPath(categoryStr)

            // Create the composite type using category-specific constructor
            val composite: Composite = when (kind) {
                "union" -> createUnion(catPath, name)
                else -> createStructure(catPath, name)
            }

            // Parse and add components
            (scriptArgs["components"] as? String)?.let { raw -> addComponents(composite, raw) }

            // Resolve into the data type manager
            val resolved = dtm.resolve(composite, null)
            if (resolved == null) { appendLine("Error: failed to resolve data type"); return }

            appendLine("Created $kind '${resolved.name}' in category ${resolved.categoryPath.path}")
            appendLine("Size: ${resolved.length} bytes")
            if (composite is StructureDataType) {
                appendLine("Components:")
                val s = resolved as Structure
                for (i in 0 until s.numComponents) {
                    val comp = s.getComponent(i)
                    appendLine("  [${i}] ${comp?.fieldName ?: ""}: ${comp?.dataType?.name ?: "?"} @ offset ${comp?.offset ?: 0}")
                }
            }
            ok = true
        } catch (e: Exception) {
            appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, ok)
        }
    }

    /** Create a StructureDataType the way Ghidra 12 expects: pass length as second arg. */
    private fun createStructure(catPath: CategoryPath, name: String): StructureDataType {
        // Ghidra 12.1: StructureDataType(CategoryPath, String) may not exist.
        // Use root constructor then set categoryPath via resolve.
        return StructureDataType(name, 1)
    }

    /** Create a UnionDataType. */
    private fun createUnion(catPath: CategoryPath, name: String): UnionDataType {
        return UnionDataType(catPath, name)
    }

    @Suppress("UNCHECKED_CAST")
    private fun addComponents(composite: Composite, raw: String) {
        val comps = try {
            com.fasterxml.jackson.databind.ObjectMapper().readValue(raw, List::class.java) as List<Map<String, Any?>>
        } catch (_: Exception) {
            appendLine("Warning: could not parse components JSON, using empty")
            emptyList()
        }
        for (comp in comps) {
            val compName = comp["name"] as? String ?: ""
            val typeName = comp["type"] as? String
            val size = (comp["size"] as? Number)?.toInt() ?: -1
            val dt: DataType = if (typeName != null) {
                resolveDataType(composite.dataTypeManager, typeName) ?: run {
                    appendLine("Warning: type '$typeName' not found, using undefined")
                    Undefined1DataType.dataType
                }
            } else {
                Undefined1DataType.dataType
            }
            val actualSize = if (size > 0 && dt.isZeroLength()) size else dt.length
            if (composite is StructureDataType) {
                composite.add(dt, if (actualSize > 0) actualSize else 1, compName, null)
            } else {
                (composite as UnionDataType).add(dt, compName, null)
            }
        }
    }

    private fun resolveDataType(dtm: DataTypeManager, name: String): DataType? {
        return dtm.getDataType(CategoryPath.ROOT, name)
    }
}
