package org.iotsplab.akiba.module.utils.io

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.apache.logging.log4j.Logger
import java.io.InputStream
import java.nio.file.Path
import kotlin.coroutines.coroutineContext

/**
 * 命令执行工具类，支持最大内存限制和超时限制
 * @param command 要执行的命令
 * @param envSource 可选的环境变量文件路径列表，会在执行命令前通过 source 加载
 * @param maxMemory 最大内存限制，单位 KB，如果大于 0，则进行内存限制检查
 * @param maxTimeout 最大时间限制，单位毫秒，如果大于 0，则进行超时限制检查
 * @param logger 日志记录器
 */
class MonitoredCommand (
    private val command: String,
    private val envSource: List<Path> = listOf(),
    private val maxMemory: Long = -1,    // Unit: KB
    private val maxTimeout: Long = -1,
    private val logger: Logger
) {
    var processInputStream: InputStream? = null
    private var currentMaxRAM: Long = 0
    private var exitCause: Int = EXIT_ITSELF

    /**
     * 运行命令并监控内存和超时
     * @return 退出方式和进程退出码
     */
    suspend fun run(): Pair<Int, Int> {
        val cmd = if (envSource.isEmpty()) command
                  else envSource.joinToString(" && ") { "source $it" } + " && $command"
        val process = ProcessBuilder("/bin/sh", "-c", cmd).redirectErrorStream(true).start()
        val pid = process.pid()

        processInputStream = process.inputStream

        val memoryMonitor: Job? = if (maxMemory > 0) {
             CoroutineScope(coroutineContext).launch {
                logger.debug("Memory monitor started")
                while (isActive && process.isAlive) {
                    val currentMemoryKb = getProcessTreeMemoryKb(pid)
                    if (currentMemoryKb != null && currentMemoryKb > currentMaxRAM) {
                        currentMaxRAM = currentMemoryKb
                    }
                    if (currentMaxRAM > maxMemory) {
                        logger.error("Memory cost meltdown detected, terminating process tree")
                        killProcessTree(pid)
                        exitCause = EXIT_MEMORY_LIMIT
                        break
                    }
                    delay(MEMORY_PEEK_INTERVAL)
                }
                val finalMemoryKb = getProcessTreeMemoryKb(pid)
                if (finalMemoryKb != null && finalMemoryKb > currentMaxRAM) {
                    currentMaxRAM = finalMemoryKb
                }
            }
        } else null

        val timeoutMonitor: Job? = if (maxTimeout > 0) {
            CoroutineScope(coroutineContext).launch {
                logger.debug("Timeout monitor started")
                delay(maxTimeout)
                logger.error("Timeout detected, terminating process tree")
                killProcessTree(pid)
                exitCause = EXIT_TIMEOUT
            }
        } else null

        memoryMonitor?.join()
        timeoutMonitor?.join()

        process.waitFor()

        return exitCause to process.exitValue()
    }

    private fun getProcessTreeMemoryKb(pid: Long): Long? {
        val pids = getChildPids(pid).toMutableList().also { it.add(pid) }
        var totalMemoryKb = 0L
        for (p in pids) {
            val statusFile = Path.of("/proc/$p/status").toFile()
            if (!statusFile.exists()) continue
            val vmRssLine = statusFile.readLines().firstOrNull { it.startsWith("VmRSS:") } ?: continue
            val memCost = vmRssLine.substringAfter("VmRSS:").substringBefore("kB").trim().toLongOrNull() ?: continue
            // Without this println, the memory cost could not be added normally and I don't know what the hell is going on
            println("Process $p memory cost: $memCost KB")
            totalMemoryKb += memCost
        }
        if (totalMemoryKb > 0) {
            logger.debug("Process tree $pid memory cost: $totalMemoryKb KB")
        }
        return totalMemoryKb
    }

    private fun getChildPids(pid: Long): List<Long> {
        val childPids = mutableListOf<Long>()
        val tasksDir = Path.of("/proc/$pid/task")
        if (!tasksDir.toFile().exists()) return childPids
        try {
            tasksDir.toFile().listFiles()?.forEach { taskDir ->
                val childrenFile = taskDir.resolve("children")
                if (childrenFile.exists()) {
                    childrenFile.readText().split("\\s+".toRegex()).filter { it.isNotEmpty() }.forEach { childPidStr ->
                        val childPid = childPidStr.toLongOrNull() ?: return@forEach
                        childPids.add(childPid)
                        childPids.addAll(getChildPids(childPid))
                    }
                }
            }
        } catch (_: Exception) {
            // Ignore permission errors or other exceptions
        }
        return childPids
    }

    private fun killProcessTree(pid: Long) {
        val stoppedPids = mutableSetOf<Long>()
        val toProcess = ArrayDeque<Long>()
        toProcess.add(pid)
        while (!toProcess.isEmpty()) {
            val currentPid = toProcess.removeFirst()
            if (stoppedPids.contains(currentPid)) continue
            try {
                Runtime.getRuntime().exec(arrayOf("kill", "-STOP", currentPid.toString())).waitFor()
                stoppedPids.add(currentPid)
            } catch (_: Exception) { }
            getChildPids(currentPid).forEach { childPid ->
                if (!stoppedPids.contains(childPid)) {
                    toProcess.add(childPid)
                }
            }
        }
        stoppedPids.forEach { p ->
            try {
                Runtime.getRuntime().exec(arrayOf("kill", "-9", p.toString())).waitFor()
            } catch (_: Exception) { }
        }
    }

    companion object {
        const val EXIT_ITSELF = 0
        const val EXIT_TIMEOUT = 1
        const val EXIT_MEMORY_LIMIT = 2

        const val MEMORY_PEEK_INTERVAL = 5_000L
    }
}