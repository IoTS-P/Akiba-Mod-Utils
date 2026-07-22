// @name: manage_data_type
// @author: Akiba
// @description: Create, query, search, edit, or delete data types using C-format definitions. Create mode: pass a C definition string (struct, union, enum, typedef) and Ghidra's CParser will parse it into the program's data type manager — no need to manually specify components as JSON. Edit mode: pass a 'name' (existing type) and a 'definition' (new C definition with the SAME name) to replace the type IN-PLACE — all functions/variables that reference the old type are automatically updated to the new layout, so no references are lost (unlike delete+create which orphans every reference). Get mode: pass a name to inspect an existing type's size, alignment, and component layout. Search mode: pass a 'query' string to find data types by type name OR by field name (case-insensitive substring match on composites); filter by kind with 'type' (struct/union/enum/typedef/composite/all). Search results are split into two sections — user-defined types created in this program (by the LLM or user) are shown FIRST, while built-in / architecture-provided types that also match are listed AFTER. Delete mode: remove a type by name. The C definition syntax supports nested structs, unions, enums, pointers, arrays, and references to other defined or built-in types.
// @parameters: action (string, default "create") - One of "create" / "edit" / "get" / "search" / "delete"; definition (string, for action=create/edit) - C definition string, e.g. "struct packet_hdr { uint8_t magic; uint16_t length; uint32_t flags; char payload[256]; };" or "union value { int i; float f; char *s; };" or "enum color { RED, GREEN, BLUE };" or "typedef unsigned int uint;"; name (string, for action=edit/get/delete) - Data type name to edit/look up/delete; query (string, for action=search, optional) - Search term matched against type names and composite field names (case-insensitive substring); if empty or omitted, all types matching the 'type' filter are listed; type (string, optional, for action=search) - Filter by data type kind: "all" (default), "struct"/"structure", "union", "enum", "typedef", "composite" (struct+union); limit (int, optional, for action=search, default 50, max 500) - Maximum number of results to return; category (string, optional) - Category path for the data type, e.g. "/myTypes" (default: resolved from the C definition or root "/")
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import ghidra.app.util.cparser.C.CParser
import ghidra.app.util.cparser.C.ParseException
import ghidra.program.model.data.*
import ghidra.util.task.TaskMonitor

class ManageDataType : AkibaScript() {

    /** A single search result hit. */
    private data class SearchHit(
        val dt: DataType,
        val isUserDefined: Boolean,
        val nameMatched: Boolean,
        val matchedFields: List<String>
    )

    override suspend fun execute() {
        val program = this.program ?: run { appendLine("Error: no program loaded"); return }
        val action = (scriptArgs["action"] as? String)?.lowercase() ?: "create"

        val dtm = program.dataTypeManager

        val txId = program.startTransaction("manage_data_type (action=$action)")
        var committed = false
        try {
            when (action) {
                "create" -> {
                    val definition = scriptArgs["definition"] as? String
                        ?: run { appendLine("Error: 'definition' parameter required for action=create"); return }
                    doCreate(dtm, definition)
                }
                "edit" -> {
                    val name = scriptArgs["name"] as? String
                        ?: run { appendLine("Error: 'name' parameter required for action=edit"); return }
                    val definition = scriptArgs["definition"] as? String
                        ?: run { appendLine("Error: 'definition' parameter required for action=edit"); return }
                    doEdit(dtm, name, definition)
                }
                "get" -> {
                    val name = scriptArgs["name"] as? String
                        ?: run { appendLine("Error: 'name' parameter required for action=get"); return }
                    doGet(dtm, name)
                }
                "search" -> {
                    val query = (scriptArgs["query"] as? String) ?: scriptArgs["keyword"] as? String ?: ""
                    val typeFilter = (scriptArgs["type"] as? String)?.lowercase() ?: "all"
                    val limit = ((scriptArgs["limit"] as? Number)?.toInt() ?: 50).coerceIn(1, 500)
                    doSearch(dtm, query, typeFilter, limit)
                }
                "delete" -> {
                    val name = scriptArgs["name"] as? String
                        ?: run { appendLine("Error: 'name' parameter required for action=delete"); return }
                    doDelete(dtm, name)
                }
                else -> appendLine("Error: unknown action '$action' (expected create / edit / get / search / delete)")
            }
            committed = true
        } catch (e: Exception) {
            appendLine("Error: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, committed)
        }
    }

    // ── create: parse C definition and store into DTM ─────────────────────

    private fun doCreate(dtm: DataTypeManager, definition: String) {
        appendLine("=== Create Data Type ===")
        appendLine("Definition: $definition")
        appendLine("")

        // CParser(dtm, true, null):
        //   storeDataType=true — the parser stores each parsed type directly
        //   into the DTM as it encounters definitions, ensuring that
        //   components (fields, nested types) are fully persisted with proper
        //   DTM-backed references. This is the critical difference from
        //   CParser(dtm) (storeDataType=false), which only builds in-memory
        //   temporary types whose components are NOT preserved after resolve().
        val parsedTypes = parseAndStore(dtm, definition)
        if (parsedTypes.isEmpty()) return

        appendLine("Created ${parsedTypes.size} data type(s):")
        for (dt in parsedTypes) {
            appendLine("")
            printDataTypeSummary(dt)
        }

        appendLine("")
        appendLine("Data type(s) are now available for use in function signatures")
        appendLine("and data definitions (e.g. via manage_func_signature or define_undefine_data).")
    }

    // ── edit: replace an existing type IN-PLACE, preserving all references ─

    private fun doEdit(dtm: DataTypeManager, name: String, definition: String) {
        appendLine("=== Edit Data Type ===")
        appendLine("Name: $name")
        appendLine("New definition: $definition")
        appendLine("")

        // 1. Find the existing type.
        val existing = findDataTypeByName(dtm, name)
        if (existing == null) {
            appendLine("Error: data type '$name' not found — use action=create to create it first.")
            return
        }

        appendLine("Existing type:")
        appendLine("  Name: ${existing.name}")
        appendLine("  Category: ${existing.categoryPath.path}")
        appendLine("  Length: ${existing.length} bytes")
        appendLine("")

        // 2. Parse with storeDataType=true so components are fully materialized
        //    in the DTM. The parser will create new types; we then use
        //    replaceDataType to swap the old type for the new one, preserving
        //    all references.
        val parsedTypes = parseAndStore(dtm, definition)
        if (parsedTypes.isEmpty()) return

        // The type we want to replace with is the one matching the name from
        // the C definition (or the first parsed type if names don't match).
        val replacementName = parsedTypes[0].name
        val replacement = parsedTypes.find { it.name == replacementName } ?: parsedTypes[0]

        if (replacement.name != existing.name) {
            appendLine("Warning: the C definition declares type '${replacement.name}' but you passed name='$name'.")
            appendLine("  The replacement will use the name from the C definition ('${replacement.name}').")
            appendLine("  All references to '$name' will be updated to '${replacement.name}'.")
            appendLine("")
        }

        // 3. Replace the existing type IN-PLACE.
        // DataTypeManager.replaceDataType updates ALL instances and references
        // (function parameters, local variables, other structs that embed this
        // type, etc.) to use the replacement — no orphans, no fallbacks.
        val resolved = try {
            dtm.replaceDataType(existing, replacement, true)
        } catch (e: DataTypeDependencyException) {
            appendLine("Error: cannot replace '$name' — the new definition depends on the existing type.")
            appendLine("  This happens when the new struct/union contains a field whose type is")
            appendLine("  the type being replaced (directly or transitively).")
            appendLine("  Restructure the definition to avoid the circular dependency.")
            return
        } catch (e: IllegalArgumentException) {
            appendLine("Error: invalid replacement: ${e.message}")
            appendLine("  Both types must be fixed-length. Dynamic/factory types cannot be replaced.")
            return
        }

        if (resolved == null) {
            appendLine("Error: dtm.replaceDataType returned null — the replacement failed silently.")
            return
        }

        appendLine("Replaced data type IN-PLACE — all references updated automatically.")
        appendLine("")
        printDataTypeSummary(resolved)

        // Report how many other types reference this one (for awareness).
        val refCount = dtm.getDataTypesContaining(resolved).size
        if (refCount > 0) {
            appendLine("")
            appendLine("Referenced by $refCount other data type(s) — all updated automatically.")
        }
    }

    // ── get: look up and display a data type ──────────────────────────────

    private fun doGet(dtm: DataTypeManager, name: String) {
        val dt = findDataTypeByName(dtm, name)
        if (dt == null) {
            appendLine("Error: data type '$name' not found")
            appendLine("  Use action=create with a C definition to create it.")
            return
        }

        appendLine("=== Data Type Info ===")
        printDataTypeSummary(dt)
    }

    // ── delete: remove a data type ────────────────────────────────────────

    private fun doDelete(dtm: DataTypeManager, name: String) {
        val dt = findDataTypeByName(dtm, name)
        if (dt == null) {
            appendLine("Error: data type '$name' not found")
            return
        }

        val affectedCount = dtm.getDataTypesContaining(dt).size
        if (affectedCount > 0) {
            appendLine("Warning: '$name' is referenced by $affectedCount other type(s).")
            appendLine("  They will fall back to their next-best match after removal.")
        }

        dtm.remove(dt, TaskMonitor.DUMMY)
        appendLine("Deleted data type '${dt.name}' from '${dt.categoryPath.path}'")
    }

    // ── search: find data types by name or field name ────────────────────

    private fun doSearch(dtm: DataTypeManager, query: String, typeFilter: String, limit: Int) {
        val q = query.lowercase()
        val queryIsBlank = q.isBlank()

        val knownFilters = setOf("", "all", "struct", "structure", "union", "enum", "typedef", "composite")
        if (typeFilter !in knownFilters) {
            appendLine("Warning: unknown type filter '$typeFilter' — searching all types. " +
                "Valid filters: all, struct, union, enum, typedef, composite.")
        }

        appendLine("=== Search Data Types ===")
        appendLine("Query: ${if (queryIsBlank) "(empty — listing all)" else "\"$query\""}  " +
            "(type filter: ${if (typeFilter.isBlank()) "all" else typeFilter}, limit: $limit)")
        appendLine("")

        val localArchive = dtm.localSourceArchive
        val localArchiveId = localArchive?.sourceArchiveID

        val hits = mutableListOf<SearchHit>()
        val iter = dtm.allDataTypes
        while (iter.hasNext()) {
            val dt = iter.next()

            if (!matchesTypeFilter(dt, typeFilter)) continue

            val nameMatched = if (queryIsBlank) false else dt.name.lowercase().contains(q)

            val matchedFields = mutableListOf<String>()
            if (!queryIsBlank && dt is Composite) {
                for (i in 0 until dt.numComponents) {
                    val comp = dt.getComponent(i) ?: continue
                    val fn = comp.fieldName ?: continue
                    if (fn.lowercase().contains(q)) {
                        matchedFields.add(fn)
                    }
                }
            }

            if (!queryIsBlank && !nameMatched && matchedFields.isEmpty()) continue

            val srcArchive = dt.sourceArchive
            val isUserDefined = (localArchiveId != null &&
                srcArchive != null &&
                srcArchive.sourceArchiveID == localArchiveId) ||
                srcArchive?.archiveType == ArchiveType.PROGRAM

            hits.add(SearchHit(dt, isUserDefined, nameMatched, matchedFields.distinct()))
        }

        if (hits.isEmpty()) {
            appendLine("No data types matched \"$query\".")
            appendLine("  Use action=create to define a new type.")
            return
        }

        hits.sortWith(compareBy({ !it.isUserDefined }, { it.dt.name.lowercase() }))

        val total = hits.size
        appendLine("Found $total match(es)${if (total > limit) " (showing first $limit)" else ""}.")

        val shown = hits.take(limit)
        val userHits = shown.filter { it.isUserDefined }
        val otherHits = shown.filter { !it.isUserDefined }

        if (userHits.isNotEmpty()) {
            appendLine("")
            appendLine("--- User-defined (this program): ${userHits.size} ---")
            for (h in userHits) printSearchHit(h)
        }
        if (otherHits.isNotEmpty()) {
            appendLine("")
            appendLine("--- Built-in / architecture / imported: ${otherHits.size} ---")
            for (h in otherHits) printSearchHit(h)
        }

        if (userHits.isEmpty()) {
            appendLine("")
            appendLine("Tip: No user-defined types matched. Use action=create to define your own " +
                "struct/union/enum/typedef, then it will appear here first.")
        }
    }

    private fun printSearchHit(h: SearchHit) {
        val dt = h.dt
        val kind = typeKindLabel(dt)
        val origin = if (h.isUserDefined) "user" else "builtin"
        val cat = dt.categoryPath?.path ?: "/"
        appendLine("  • ${dt.name}  [$kind, ${dt.length} bytes, $origin]  ($cat)")
        if (h.nameMatched && h.matchedFields.isEmpty()) {
            appendLine("      matched: name")
        } else if (!h.nameMatched && h.matchedFields.isNotEmpty()) {
            appendLine("      matched field(s): ${h.matchedFields.joinToString(", ")}")
        } else if (h.nameMatched && h.matchedFields.isNotEmpty()) {
            appendLine("      matched: name + field(s) ${h.matchedFields.joinToString(", ")}")
        }
    }

    private fun matchesTypeFilter(dt: DataType, filter: String): Boolean {
        return when (filter) {
            "", "all" -> true
            "struct", "structure" -> dt is Structure
            "union" -> dt is Union
            "enum" -> dt is ghidra.program.model.data.Enum
            "typedef" -> dt is TypeDef
            "composite" -> dt is Composite
            else -> true
        }
    }

    private fun typeKindLabel(dt: DataType): String {
        return when (dt) {
            is Structure -> "struct"
            is Union -> "union"
            is ghidra.program.model.data.Enum -> "enum"
            is TypeDef -> "typedef"
            is Composite -> "composite"
            else -> dt.javaClass.simpleName
        }
    }

    // ── Parse C definition with storeDataType=true (shared by create & edit) ─

    /**
     * Parse a C definition string using CParser with storeDataType=true.
     *
     * CRITICAL: CParser(dtm, true, null) stores each parsed type directly into
     * the DTM as it parses, ensuring that struct/union/enum components are
     * fully persisted with proper DTM-backed DataType references. This is the
     * only way to get a complete type definition stored in the program — using
     * CParser(dtm) (storeDataType=false) produces in-memory temporary types
     * whose components are lost when resolved.
     *
     * After parsing, the method collects ALL parsed types from the parser's
     * getComposites() / getEnums() / getTypes() maps and returns them.
     */
    private fun parseAndStore(dtm: DataTypeManager, definition: String): List<DataType> {
        // Auto-append a missing trailing semicolon — CParser requires it.
        val normalized = definition.trim().let {
            if (it.endsWith(";")) it else "$it;"
        }
        if (normalized != definition.trim()) {
            appendLine("Note: auto-appended missing trailing ';'.")
        }

        // storeDataType=true: parser stores types into DTM during parsing.
        // subDTMgrs=null: only use the program's DTM (no external archives).
        val parser = CParser(dtm, true, null)

        try {
            parser.parse(normalized)
        } catch (e: ParseException) {
            appendLine("Error: failed to parse C definition:")
            appendLine("  ${e.message}")
            appendLine("")
            appendLine("Common issues:")
            appendLine("  - Missing semicolon at the end (auto-appended, but check for other issues)")
            appendLine("  - Unknown type names (define them first or use built-in types)")
            appendLine("  - Syntax errors in struct/union/enum body")
            return emptyList()
        }

        // Collect all parsed types from the parser's maps.
        // getComposites() → struct/union definitions
        // getEnums() → enum definitions
        // getTypes() → typedef definitions
        // getFunctions() → function signature definitions
        val allParsed = mutableListOf<DataType>()
        allParsed += parser.getComposites().values
        allParsed += parser.getEnums().values
        allParsed += parser.getTypes().values

        if (allParsed.isEmpty()) {
            appendLine("Error: CParser parsed the definition but produced no data types.")
            appendLine("  Ensure the definition contains a struct/union/enum/typedef definition,")
            appendLine("  not just a declaration (e.g. 'struct foo;' is a declaration,")
            appendLine("  'struct foo { int x; };' is a definition).")
            return emptyList()
        }

        return allParsed
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun findDataTypeByName(dtm: DataTypeManager, name: String): DataType? {
        val rootDt = dtm.getDataType(CategoryPath.ROOT, name)
        if (rootDt != null) return rootDt
        return searchCategory(dtm.rootCategory, name)
    }

    private fun searchCategory(cat: Category, name: String): DataType? {
        for (dt in cat.dataTypes) {
            if (dt.name == name) return dt
        }
        for (subCat in cat.categories) {
            searchCategory(subCat, name)?.let { return it }
        }
        return null
    }

    private fun printDataTypeSummary(dt: DataType) {
        appendLine("Name: ${dt.name}")
        appendLine("  Category: ${dt.categoryPath.path}")
        appendLine("  Type: ${dt.javaClass.simpleName}")
        appendLine("  Length: ${dt.length} bytes")
        appendLine("  Alignment: ${dt.alignment} bytes")
        if (dt.description.isNotBlank()) {
            appendLine("  Description: ${dt.description}")
        }

        if (dt is Composite) {
            appendLine("")
            printCompositeLayout(dt)
        } else if (dt is ghidra.program.model.data.Enum) {
            appendLine("")
            printEnumLayout(dt)
        } else if (dt is TypeDef) {
            appendLine("")
            appendLine("  Typedef target: ${dt.dataType.name} (${dt.dataType.length} bytes)")
        } else if (dt is FunctionDefinitionDataType) {
            appendLine("")
            appendLine("  Function signature: ${dt.prototypeString}")
        }
    }

    private fun printCompositeLayout(c: Composite) {
        if (c is Structure) {
            appendLine("Layout (structure, ${c.numComponents} component(s)):")
            for (i in 0 until c.numComponents) {
                val comp = c.getComponent(i) ?: continue
                val fieldName = comp.fieldName ?: "<unnamed>"
                appendLine("  [$i] offset 0x${comp.offset.toString(16)}: $fieldName: ${comp.dataType.name} (${comp.length} bytes)")
            }
        } else if (c is Union) {
            appendLine("Layout (union, ${c.numComponents} member(s)):")
            for (i in 0 until c.numComponents) {
                val comp = c.getComponent(i) ?: continue
                val fieldName = comp.fieldName ?: "<unnamed>"
                appendLine("  [$i] $fieldName: ${comp.dataType.name} (${comp.length} bytes)")
            }
        }
    }

    private fun printEnumLayout(e: ghidra.program.model.data.Enum) {
        val names = e.getNames()
        appendLine("Enum values (${names.size}):")
        for (name in names) {
            appendLine("  $name = ${e.getValue(name)}")
        }
    }
}
