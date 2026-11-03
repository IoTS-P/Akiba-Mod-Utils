package org.iotsplab.akiba.module

/**
 * Configuration for AkibaUtils text-export mode.
 *
 * [startProcess] enters export mode instead of script seeding when this config is
 * supplied via `@WithConfigClass`; the `--export` CLI flag produces it, so options
 * flow through the standard module-config pipeline with no environment variables.
 * Field defaults match `ProjectTextExportRequest` so the server can serialize a
 * request body straight into a config-file section.
 */
data class TextExportConfig(
    /** Which content sections to emit: listing, comments, functions, data, decompile. */
    val contents: List<String> = listOf("listing", "comments", "functions"),
    val includeComments: Boolean = true,
    val includeEolComment: Boolean = true,
    val includePlateComment: Boolean = true,
    val includePreComment: Boolean = true,
    val includePostComment: Boolean = false,
    val includeRepeatableComment: Boolean = false,
    val includeDecompile: Boolean = false,
    val decompileTimeoutSec: Int = 30,
    val includeData: Boolean = true,
    val includeUndefined: Boolean = false,
    /** Regex pattern; only functions whose name matches are exported. */
    val functionFilter: String? = null,
    /** Optional address-range restriction. */
    val addressFilter: TextExportAddressFilterConfig? = null,
    /** 0 = no limit. */
    val maxFunctions: Int = 0,
    /** Functions larger than this (in bytes) are listed but their body is skipped. */
    val maxFunctionSize: Int = 1 shl 20,
    /** Sort functions by: "address" (default), "name", or "size". */
    val sortBy: String = "address",
    /** Optional regex; only programs whose name matches are exported. */
    val programFilter: String? = null,
)

data class TextExportAddressFilterConfig(
    val start: String,
    val end: String,
)
