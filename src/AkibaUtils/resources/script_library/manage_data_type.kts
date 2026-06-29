// @name: manage_data_type
// @author: Akiba
// @description: Create, query, update, or delete a structure/union data type in the program's data type manager. action=get returns the existing type's length, alignment, and component list. action=update edits components in place (rename via newName, replace / insert / delete individual components) so iterative refinement does not require delete-then-recreate. action=delete removes the type outright. For complex types built up gradually, prefer create with components, then update with componentEdits between function discoveries.
// @parameters: name (string) - Data type name; kind (string, optional, for create) - "structure" or "union" (default "structure"); category (string, optional) - Category path, e.g. "/myTypes" (default "/"); action (string, default "create") - One of "create" / "get" / "update" / "delete"; components (string, optional, for create/update) - JSON array of component objects for create (or wholesale replacement on update): [{"name":"field1","type":"int","size":4}, {"name":"field2","type":"char*"}]. 'type' is the type name; 'size' is optional (only for non-pointer types when you want a specific byte length). If 'type' is omitted, the component will use 'undefined' with the given size; newName (string, optional, for update) - Rename the data type; newCategory (string, optional, for update) - Move to a different category; componentEdits (string, optional, for update on existing structures/unions) - JSON array of per-component edits applied in order: [{"index":1,"action":"replace","type":"int","name":"count"},{"index":2,"action":"delete"},{"index":3,"action":"insert","type":"int","name":"extra"}]. Allowed per-element action: replace / delete / insert. After inserts the supplied `index` is the position in the original structure.

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.data.*
import ghidra.util.task.TaskMonitor

class ManageDataType : AkibaScript() {
    override suspend fun execute() {
        val program = currentProgram ?: run { appendLine("Error: no program loaded"); return }
        val name = scriptArgs["name"] as? String
            ?: run { appendLine("Error: 'name' parameter required"); return }
        val kind = (scriptArgs["kind"] as? String)?.lowercase() ?: "structure"
        val categoryStr = (scriptArgs["category"] as? String) ?: "/"
        val action = (scriptArgs["action"] as? String)?.lowercase() ?: "create"
        val newName = scriptArgs["newName"] as? String
        val newCategoryStr = (scriptArgs["newCategory"] as? String)
        val componentsRaw = (scriptArgs["components"] as? String)?.takeIf { it.isNotBlank() }
        val componentEditsRaw = (scriptArgs["componentEdits"] as? String)?.takeIf { it.isNotBlank() }

        val dtm = program.dataTypeManager
        val catPath = CategoryPath(categoryStr)
        if (!dtm.containsCategory(catPath) && action != "create") {
            appendLine("Error: category '$categoryStr' does not exist (use 'create' to make a fresh structure in it)")
            return
        }

        val txId = program.startTransaction("manage_data_type (action=$action, name=$name)")
        var committed = false
        try {
            when (action) {
                "create" -> doCreate(dtm, catPath, name, kind, componentsRaw)
                "get" -> doGet(dtm, catPath, name)
                "update" -> doUpdate(dtm, catPath, name, newName, newCategoryStr, componentsRaw, componentEditsRaw)
                "delete" -> doDelete(dtm, catPath, name)
                else -> appendLine("Error: unknown action '$action' (expected create / get / update / delete)")
            }
            committed = true
        } catch (e: Exception) {
            appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, committed)
        }
    }

    // ── create ─────────────────────────────────────────────────────────────

    @Suppress("UNCHECKED_CAST")
    private fun doCreate(dtm: DataTypeManager, catPath: CategoryPath, name: String, kind: String, componentsRaw: String?) {
        // Reject duplicates up-front so the caller gets a clear error rather
        // than a silently-renamed conflicting type.
        if (dtm.getDataType(catPath, name) != null) {
            appendLine("Error: data type '$name' already exists in '$catPath' — use action=update to modify it")
            return
        }
        val composite: Composite = if (kind == "union") UnionDataType(catPath, name)
        else StructureDataType(name, 1)
        componentsRaw?.let { addComponents(composite, it) }
        val resolved = dtm.resolve(composite, null)
        if (resolved == null) { appendLine("Error: failed to resolve data type"); return }
        appendLine("Created $kind '${resolved.name}' in category ${resolved.categoryPath.path}")
        appendLine("Size: ${resolved.length} bytes")
        printCompositeLayout(resolved)
    }

    // ── get ────────────────────────────────────────────────────────────────

    private fun doGet(dtm: DataTypeManager, catPath: CategoryPath, name: String) {
        val dt = dtm.getDataType(catPath, name)
        if (dt == null) { appendLine("Error: data type '$name' not found in '$catPath'"); return }
        appendLine("Data type: ${dt.name}")
        appendLine("  Category: ${dt.categoryPath.path}")
        appendLine("  Length:   ${dt.length} bytes")
        appendLine("  Alignment:${dt.alignment} bytes")
        if (dt.description.isNotBlank()) appendLine("  Description: ${dt.description}")
        if (dt is Composite) printCompositeLayout(dt)
    }

    // ── update ─────────────────────────────────────────────────────────────

    @Suppress("UNCHECKED_CAST")
    private fun doUpdate(
        dtm: DataTypeManager,
        catPath: CategoryPath,
        name: String,
        newName: String?,
        newCategoryStr: String?,
        componentsRaw: String?,
        componentEditsRaw: String?,
    ) {
        val existing = dtm.getDataType(catPath, name)
        if (existing == null) { appendLine("Error: data type '$name' not found in '$catPath'"); return }

        // We only support update on Composite (Structure / Union). Other
        // built-ins (typedefs, enums, pointers) need a different code path.
        val composite = existing as? Composite
        if (composite == null) {
            appendLine("Error: action=update only supports structure / union (got ${existing.displayName})")
            return
        }

        // (1) Wholesale replacement: components JSON provided.
        if (componentsRaw != null) {
            // Clear all current components first.
            while (composite.numComponents > 0) {
                try { composite.delete(0) } catch (_: Exception) { break }
            }
            addComponents(composite, componentsRaw)
            appendLine("Replaced all components of '${existing.name}' with the new component list.")
        }

        // (2) Per-component edits (apply on top of (1) if both given).
        if (componentEditsRaw != null) {
            val edits = try {
                com.fasterxml.jackson.databind.ObjectMapper().readValue(componentEditsRaw, List::class.java)
                    .map { (it as? Map<String, Any?>) ?: emptyMap() }
            } catch (e: Exception) {
                appendLine("Error: 'componentEdits' is not a valid JSON array: ${e.message}")
                return
            }
            // Process edits in REVERSE index order so earlier deletions/inserts
            // do not shift the indices of later edits.
            val sorted = edits
                .mapIndexed { idx, e -> Triple(idx, (e["index"] as? Number)?.toInt() ?: -1, e) }
                .filter { it.second >= 0 }
                .sortedByDescending { it.second }
            var okCount = 0
            for ((rawIdx, idx, edit) in sorted) {
                val act = (edit["action"] as? String)?.lowercase() ?: ""
                when (act) {
                    "delete" -> {
                        if (idx >= composite.numComponents) {
                            appendLine("[#$rawIdx] delete: index $idx out of range (have ${composite.numComponents} components)")
                            continue
                        }
                        val nm = composite.getComponent(idx)?.fieldName ?: ""
                        composite.delete(idx)
                        appendLine("[#$rawIdx] delete: removed component at index $idx (was '$nm')")
                        okCount++
                    }
                    "replace" -> {
                        if (idx >= composite.numComponents) {
                            appendLine("[#$rawIdx] replace: index $idx out of range (have ${composite.numComponents} components)")
                            continue
                        }
                        val newTypeName = edit["type"] as? String
                        val newCompName = edit["name"] as? String
                        val size = (edit["size"] as? Number)?.toInt() ?: -1
                        if (newTypeName == null) {
                            appendLine("[#$rawIdx] replace: missing 'type'")
                            continue
                        }
                        val dt = resolveDataType(composite.dataTypeManager, newTypeName)
                        if (dt == null) {
                            appendLine("[#$rawIdx] replace: type '$newTypeName' not found")
                            continue
                        }
                        val actualSize = if (size > 0 && dt.isZeroLength) size else dt.length
                        if (composite is StructureDataType) {
                            composite.replaceAtOffset(idx, dt, actualSize, newCompName, null)
                        } else {
                            // UnionDataType: replace has no offset semantics.
                            // Drop the slot then add a fresh one in its place.
                            composite.delete(idx)
                            (composite as UnionDataType).add(dt, newCompName, null)
                        }
                        appendLine("[#$rawIdx] replace: index $idx -> ${dt.name}${if (newCompName != null) " '$newCompName'" else ""}")
                        okCount++
                    }
                    "insert" -> {
                        val newTypeName = edit["type"] as? String
                        val newCompName = edit["name"] as? String
                        val size = (edit["size"] as? Number)?.toInt() ?: -1
                        if (newTypeName == null) {
                            appendLine("[#$rawIdx] insert: missing 'type'")
                            continue
                        }
                        val dt = resolveDataType(composite.dataTypeManager, newTypeName)
                        if (dt == null) {
                            appendLine("[#$rawIdx] insert: type '$newTypeName' not found")
                            continue
                        }
                        val actualSize = if (size > 0 && dt.isZeroLength) size else dt.length
                        val insertIdx = idx.coerceIn(0, composite.numComponents)
                        if (composite is StructureDataType) {
                            composite.insert(insertIdx, dt, actualSize, newCompName, null)
                        } else {
                            (composite as UnionDataType).add(dt, newCompName, null)
                        }
                        appendLine("[#$rawIdx] insert: ${dt.name} at index $insertIdx${if (newCompName != null) " '$newCompName'" else ""}")
                        okCount++
                    }
                    else -> appendLine("[#$rawIdx] unknown action '$act' (expected replace / delete / insert)")
                }
            }
            appendLine("Component edits: ${sorted.size} requested, $okCount applied.")
        }

        // (3) Rename / recategorise, last so the rename reflects any structural changes.
        if (newName != null || newCategoryStr != null) {
            val targetCat = if (newCategoryStr != null) CategoryPath(newCategoryStr) else composite.categoryPath
            composite.setNameAndCategory(targetCat, newName ?: composite.name)
            appendLine("Renamed/moved data type to '${composite.name}' in ${composite.categoryPath.path}")
        }

        // (4) Re-resolve so the manager gives us the canonical unique name
        // (the manager may have appended a suffix on rename conflicts).
        val resolved = dtm.resolve(composite, null)
        if (resolved != null) {
            appendLine("Final state:")
            appendLine("  Name:     ${resolved.name}")
            appendLine("  Category: ${resolved.categoryPath.path}")
            appendLine("  Length:   ${resolved.length} bytes")
            printCompositeLayout(resolved as Composite)
        }
    }

    // ── delete ─────────────────────────────────────────────────────────────

    private fun doDelete(dtm: DataTypeManager, catPath: CategoryPath, name: String) {
        val dt = dtm.getDataType(catPath, name)
        if (dt == null) { appendLine("Error: data type '$name' not found in '$catPath'"); return }
        val affectedCount = dtm.getDataTypesContaining(dt).size
        if (affectedCount > 0) {
            appendLine("Warning: '$name' is referenced by $affectedCount other type(s) — they will fall back to their next-best match after removal.")
        }
        dtm.remove(dt, TaskMonitor.DUMMY)
        appendLine("Deleted data type '$name' from '$catPath'")
    }

    // ── shared layout printer ──────────────────────────────────────────────

    private fun printCompositeLayout(c: Composite) {
        if (c !is StructureDataType) {
            appendLine("Kind: union (${c.numComponents} member(s))")
            for (i in 0 until c.numComponents) {
                val comp = c.getComponent(i) ?: continue
                appendLine("  [$i] ${comp.fieldName ?: "<unnamed>"}: ${comp.dataType.name}")
            }
            return
        }
        appendLine("Components:")
        for (i in 0 until c.numComponents) {
            val comp = c.getComponent(i) ?: continue
            appendLine("  [$i] ${comp.fieldName ?: "<unnamed>"}: ${comp.dataType.name} @ offset ${comp.offset}")
        }
    }

    // ── component helpers (preserved from create_data_type) ───────────────

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