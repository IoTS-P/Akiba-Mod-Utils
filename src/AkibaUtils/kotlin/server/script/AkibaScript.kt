package org.iotsplab.akiba.module.server.script

import org.iotsplab.akiba.module.AkibaModule
import ghidra.program.model.listing.Program

/**
 * Abstract base class for Akiba scripts.
 * Scripts extend this class and implement the [execute] method.
 * They provide a simplified interface for writing analysis code that runs against a single binary.
 *
 * Example usage:
 * ```kotlin
 * class MyScript : AkibaScript(
 *     saveResult = true,
 *     maxOutputSize = 1024 * 1024  // 1MB
 * ) {
 *     override suspend fun execute() {
 *         val program = getProgram()
 *         logger.info("Processing ${program.name}")
 *         // ... analysis code
 *         appendOutput("Analysis complete!")
 *     }
 * }
 * ```
 *
 * @property saveResult Whether to save the script result to the database
 * @property maxOutputSizeBytes Maximum size for output (in bytes). User can set lower but not exceed this.
 * @property description A brief description of what the script does
 */
abstract class AkibaScript(
    val saveResult: Boolean = true,
    val maxOutputSizeBytes: Long = 10 * 1024 * 1024, // 10MB default
    val description: String = ""
) : AkibaModule() {

    private val outputBuilder = StringBuilder()

    /**
     * Get the Ghidra Program object for the current binary being analyzed.
     * @return The Ghidra Program, or null if not available
     */
    fun getCurrentProgram(): Program? = program

    /**
     * Get the binary ID being processed
     */
    fun getBinaryId(): Int = id

    /**
     * Append output to the script's output buffer.
     * Output will be truncated if it exceeds [maxOutputSizeBytes].
     */
    protected fun appendOutput(text: String) {
        if (outputBuilder.length < maxOutputSizeBytes) {
            val remaining = maxOutputSizeBytes - outputBuilder.length
            if (text.length <= remaining) {
                outputBuilder.append(text)
            } else {
                outputBuilder.append(text.substring(0, remaining.toInt()))
                outputBuilder.append("\n... (output truncated)")
            }
        }
    }

    /**
     * Append output with a newline
     */
    protected fun appendLine(text: String) {
        appendOutput(text + "\n")
    }

    /**
     * Clear the output buffer
     */
    protected fun clearOutput() {
        outputBuilder.clear()
    }

    /**
     * Get the current output
     */
    fun getOutput(): String = outputBuilder.toString()

    /**
     * Main execution method - implement with script logic
     */
    abstract suspend fun execute()

    final override suspend fun startProcess() {
        clearOutput()
        execute()
    }
}