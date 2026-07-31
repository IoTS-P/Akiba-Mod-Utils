// @name: run_angr_script
// @author: Akiba
// @description: Run a Python angr analysis script against the loaded binary. The binary's absolute path is passed to the script via the AKIBA_BINARY_PATH environment variable. Uses a virtual environment at ~/.akiba/venv (auto-created and angr auto-installed if missing). The script path is relative to the workspace root or an absolute path.
// @parameters: scriptPath (string, required) - Path to the Python script to run. Relative paths resolve against the agent workspace root; absolute paths are also accepted. timeout (integer, optional) - Maximum execution time in seconds (default 120, max 600). args (string, optional) - Extra command-line arguments to pass to the Python script (passed as-is after shell-safe splitting).
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

class RunAngrScript : AkibaScript() {

    companion object {
        /** Fixed environment variable name carrying the binary's absolute path. */
        const val ENV_BINARY_PATH = "AKIBA_BINARY_PATH"

        /** Location of the Python virtual environment used for angr. */
        val VENV_DIR: Path = Path.of(System.getProperty("user.home"), ".akiba", "venv")

        /** Default execution timeout in seconds. */
        const val DEFAULT_TIMEOUT_SEC = 120

        /** Maximum allowed timeout in seconds. */
        const val MAX_TIMEOUT_SEC = 600
    }

    override suspend fun execute() {
        val scriptPathStr = scriptArgs["scriptPath"] as? String
            ?: run { appendLine("Error: 'scriptPath' parameter is required"); return }

        val timeoutSec = ((scriptArgs["timeout"] as? Number)?.toInt() ?: DEFAULT_TIMEOUT_SEC)
            .coerceIn(1, MAX_TIMEOUT_SEC)

        val extraArgsRaw = (scriptArgs["args"] as? String)?.takeIf { it.isNotBlank() }

        // ── Resolve the binary file path ──────────────────────────────
        val binaryPath = usingFile.absolutePath
        if (!File(binaryPath).exists()) {
            appendLine("Error: binary file not found at '$binaryPath'")
            appendLine("(usingFile resolved to: ${usingFile})")
            return
        }

        // ── Resolve the script path ───────────────────────────────────
        // Relative paths resolve against the caller's workspace directory
        // (injected by ScriptLibraryTool as _akiba_workspace_dir).
        val wsDirStr = (scriptArgs["_akiba_workspace_dir"] as? String)
            ?: workspaceDir.toString()
        val wsDir = File(wsDirStr)

        val scriptFile = if (File(scriptPathStr).isAbsolute) {
            File(scriptPathStr)
        } else {
            File(wsDir, scriptPathStr)
        }

        if (!scriptFile.exists()) {
            appendLine("Error: Python script not found: '$scriptPathStr'")
            appendLine("  Resolved to: ${scriptFile.absolutePath}")
            appendLine("  Workspace root: ${wsDir.absolutePath}")
            appendLine("  Tip: Use write_workspace_file to save your angr script to the workspace first,")
            appendLine("       then pass the relative path to this tool.")
            return
        }
        if (!scriptFile.isFile) {
            appendLine("Error: script path is not a regular file: '${scriptFile.absolutePath}'")
            return
        }

        // ── Ensure the virtual environment + angr are ready ───────────
        appendLine("=== angr Script Runner ===")
        appendLine("Binary:  $binaryPath")
        appendLine("Script:  ${scriptFile.absolutePath}")
        appendLine("Timeout: ${timeoutSec}s")
        appendLine("Env var: $ENV_BINARY_PATH=<binary path>")
        appendLine("")

        val venvReady = try {
            ensureVenvWithAngr()
        } catch (e: Exception) {
            appendLine("Error: failed to prepare Python virtual environment: ${e.message}")
            return
        }
        if (!venvReady) {
            appendLine("Error: Python virtual environment could not be prepared. See logs above.")
            return
        }

        val pythonBin = VENV_DIR.resolve("bin").resolve("python").toFile()
        if (!pythonBin.exists()) {
            // Windows fallback
            val pythonExe = VENV_DIR.resolve("Scripts").resolve("python.exe").toFile()
            if (!pythonExe.exists()) {
                appendLine("Error: python executable not found in venv at $VENV_DIR")
                return
            }
            runPythonScript(pythonExe, scriptFile, binaryPath, extraArgsRaw, timeoutSec)
            return
        }
        runPythonScript(pythonBin, scriptFile, binaryPath, extraArgsRaw, timeoutSec)
    }

    /**
     * Ensure ~/.akiba/venv exists with angr installed.
     *
     * - If the venv directory doesn't exist, create it via `python3 -m venv`.
     * - If angr is not importable, pip-install it.
     *
     * Returns true on success, false on failure.
     */
    private fun ensureVenvWithAngr(): Boolean {
        val venvDir = VENV_DIR.toFile()

        // Step 1: create venv if missing
        if (!venvDir.exists() || !venvDir.isDirectory) {
            appendLine("[venv] Creating virtual environment at $VENV_DIR ...")
            val createResult = runCommand(
                listOf("python3", "-m", "venv", VENV_DIR.toString()),
                env = null,
                timeoutSec = 120
            )
            if (createResult.exitCode != 0) {
                appendLine("[venv] FAILED to create venv (exit ${createResult.exitCode}):")
                appendLine(createResult.stderr.take(2000))
                return false
            }
            appendLine("[venv] Virtual environment created.")
        } else {
            appendLine("[venv] Using existing virtual environment at $VENV_DIR")
        }

        // Step 2: check if angr is importable
        val pythonBin = VENV_DIR.resolve("bin").resolve("python").toFile()
            .takeIf { it.exists() }
            ?: VENV_DIR.resolve("Scripts").resolve("python.exe").toFile()

        if (!pythonBin.exists()) {
            appendLine("[venv] Error: python executable not found in venv")
            return false
        }

        appendLine("[venv] Checking if angr is installed ...")
        val checkResult = runCommand(
            listOf(pythonBin.absolutePath, "-c", "import angr; print(angr.__version__)"),
            env = null,
            timeoutSec = 30
        )

        if (checkResult.exitCode == 0 && checkResult.stdout.contains(".")) {
            // angr is installed — extract version
            val version = checkResult.stdout.trim().lines().lastOrNull() ?: "unknown"
            appendLine("[venv] angr $version is already installed.")
            return true
        }

        // Step 3: install angr
        appendLine("[venv] angr not found; installing via pip ...")
        val pipBin = VENV_DIR.resolve("bin").resolve("pip").toFile()
            .takeIf { it.exists() }
            ?: VENV_DIR.resolve("Scripts").resolve("pip.exe").toFile()

        val pipCmd = if (pipBin.exists()) {
            listOf(pipBin.absolutePath, "install", "--no-input", "angr")
        } else {
            listOf(pythonBin.absolutePath, "-m", "pip", "install", "--no-input", "angr")
        }

        val installResult = runCommand(pipCmd, env = null, timeoutSec = 600)
        if (installResult.exitCode != 0) {
            appendLine("[venv] FAILED to install angr (exit ${installResult.exitCode}):")
            appendLine(installResult.stderr.take(3000))
            return false
        }
        appendLine("[venv] angr installed successfully.")
        return true
    }

    /**
     * Run the user's Python script with the binary path injected as an
     * environment variable.  Uses ProcessBuilder (argv form) — never
     * shells out — to satisfy command-injection safety requirements.
     */
    private fun runPythonScript(
        pythonBin: File,
        scriptFile: File,
        binaryPath: String,
        extraArgsRaw: String?,
        timeoutSec: Int
    ) {
        // Build argv.  We do NOT use shell; extra args are split on
        // whitespace (simple, safe — no shell metachar expansion).
        val argv = mutableListOf(pythonBin.absolutePath, scriptFile.absolutePath)
        if (!extraArgsRaw.isNullOrBlank()) {
            argv.addAll(splitArgs(extraArgsRaw))
        }

        // Inject the binary path as a fixed-name environment variable.
        val env = System.getenv().toMutableMap()
        env[ENV_BINARY_PATH] = binaryPath

        appendLine("[run] Executing: ${argv.joinToString(" ")}")
        appendLine("[run] $ENV_BINARY_PATH=$binaryPath")
        appendLine("")

        val result = runCommand(argv, env, timeoutSec)

        // ── Emit stdout ──
        if (result.stdout.isNotEmpty()) {
            appendLine("=== stdout ===")
            appendLine(result.stdout)
        } else {
            appendLine("=== stdout === (empty)")
        }

        // ── Emit stderr ──
        if (result.stderr.isNotEmpty()) {
            appendLine("")
            appendLine("=== stderr ===")
            appendLine(result.stderr)
        }

        appendLine("")
        appendLine("=== Exit code: ${result.exitCode} ===")
        appendLine("Wall time: ${result.durationMs}ms")

        if (result.timedOut) {
            appendLine("⚠️ TIMEOUT: script was killed after ${timeoutSec}s.")
            appendLine("  Increase the 'timeout' parameter (max $MAX_TIMEOUT_SEC) if the script needs more time.")
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private data class CommandResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
        val durationMs: Long,
        val timedOut: Boolean
    )

    /**
     * Run an external command (argv form), capturing stdout/stderr.
     * Never uses a shell — satisfies CWE-78 (command injection).
     */
    private fun runCommand(
        argv: List<String>,
        env: Map<String, String>?,
        timeoutSec: Int
    ): CommandResult {
        val pb = ProcessBuilder(argv).apply {
            redirectErrorStream(false)
            if (env != null) {
                environment().clear()
                environment().putAll(env)
            }
        }
        val start = System.currentTimeMillis()
        val process = try {
            pb.start()
        } catch (e: Exception) {
            return CommandResult(-1, "", "Failed to start process: ${e.message}", 0, false)
        }

        // Read stdout and stderr concurrently to avoid pipe deadlock.
        val stdoutText = StringBuilder()
        val stderrText = StringBuilder()
        val stdoutThread = Thread {
            try {
                process.inputStream.bufferedReader().use { reader ->
                    val buf = CharArray(4096)
                    var n: Int
                    while (reader.read(buf).also { n = it } > 0) {
                        stdoutText.append(buf, 0, n)
                        // Cap at 1 MB to avoid OOM on runaway output.
                        if (stdoutText.length > 1_048_576) {
                            stdoutText.append("\n... [stdout truncated at 1 MB]")
                            break
                        }
                    }
                }
            } catch (_: Exception) { }
        }
        val stderrThread = Thread {
            try {
                process.errorStream.bufferedReader().use { reader ->
                    val buf = CharArray(4096)
                    var n: Int
                    while (reader.read(buf).also { n = it } > 0) {
                        stderrText.append(buf, 0, n)
                        if (stderrText.length > 512 * 1024) {
                            stderrText.append("\n... [stderr truncated at 512 KB]")
                            break
                        }
                    }
                }
            } catch (_: Exception) { }
        }
        stdoutThread.start()
        stderrThread.start()

        val finished = process.waitFor(timeoutSec.toLong(), TimeUnit.SECONDS)
        val durationMs = System.currentTimeMillis() - start

        if (!finished) {
            process.destroyForcibly()
            stdoutThread.join(2000)
            stderrThread.join(2000)
            return CommandResult(-1, stdoutText.toString(), stderrText.toString(), durationMs, true)
        }

        stdoutThread.join(3000)
        stderrThread.join(3000)
        return CommandResult(process.exitValue(), stdoutText.toString(), stderrText.toString(), durationMs, false)
    }

    /**
     * Split a string into shell-like argv tokens on whitespace.
     * Does NOT interpret quotes or escapes — this is intentionally
     * simple to avoid any shell-expansion attack surface.
     * Callers needing complex argument passing should write their
     * argument values into the Python script directly.
     */
    private fun splitArgs(raw: String): List<String> =
        raw.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
}
