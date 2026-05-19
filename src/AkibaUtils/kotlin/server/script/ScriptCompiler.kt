package org.iotsplab.akiba.module.server.script

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.io.StringWriter
import java.io.Writer
import java.net.URI
import java.net.URL
import java.nio.file.Files
import javax.tools.Diagnostic
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.SimpleJavaFileObject
import javax.tools.ToolProvider
import kotlin.reflect.KClass

data class CompiledScript(
    val className: String,
    val classBytes: ByteArray,
    val warnings: List<String> = emptyList()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CompiledScript) return false
        return className == other.className
    }

    override fun hashCode(): Int = className.hashCode()
}

class ByteArrayJavaFileObject(
    private val binClassName: String,
    kind: JavaFileObject.Kind
) : SimpleJavaFileObject(
    URI.create("mem:///$binClassName.class"),
    kind
) {
    private val baos = ByteArrayOutputStream()

    override fun openOutputStream(): OutputStream = baos

    fun getBytes(): ByteArray = baos.toByteArray()
}

object ScriptCompiler {
    private var kotlinCompiler: Any? = null
    private var kotlinCompilerClass: KClass<*>? = null

    init {
        try {
            loadKotlinCompiler()
        } catch (e: Exception) {
            System.err.println("Warning: Kotlin compiler not available. Only Java scripts can be compiled. ${e.message}")
        }
    }

    private fun loadKotlinCompiler() {
        val classLoader = this::class.java.classLoader
        val kotlinCompilerFactoryClass = classLoader.loadClass("kotlin.script.experimental.jvm.compiler.KotlinJspCompilerFactory")
        val factory = kotlinCompilerFactoryClass.getDeclaredConstructor().newInstance()
        val compilerMethod = kotlinCompilerFactoryClass.getMethod("getCompiler")
        kotlinCompiler = compilerMethod.invoke(factory)
        kotlinCompilerClass = kotlinCompiler as? KClass<*>
    }

    fun isKotlinAvailable(): Boolean = kotlinCompiler != null

    fun compile(
        source: String,
        className: String,
        additionalDependencies: List<URL> = emptyList()
    ): CompiledScript {
        val isKotlin = source.contains("fun ") || (source.contains("class ") && source.contains("suspend"))
        return if (isKotlin && isKotlinAvailable()) {
            compileKotlin(source, className, additionalDependencies)
        } else if (isKotlin) {
            throw CompilationException("Kotlin compiler not available. Please use Java syntax.")
        } else {
            compileJava(source, className, additionalDependencies)
        }
    }

    private fun compileJava(
        source: String,
        className: String,
        @Suppress("UNUSED_PARAMETER") additionalDependencies: List<URL>
    ): CompiledScript {
        val compiler = ToolProvider.getSystemJavaCompiler()
            ?: throw CompilationException("Java compiler not available")

        val diagnostics = DiagnosticCollector<JavaFileObject>()

        val sourceFile = object : SimpleJavaFileObject(
            URI.create("string:///$className.java"),
            JavaFileObject.Kind.SOURCE
        ) {
            override fun getCharContent(ignored: Boolean): CharSequence = source
        }

        val classFile = ByteArrayJavaFileObject(className, JavaFileObject.Kind.CLASS)

        @Suppress("UNCHECKED_CAST")
        val task = compiler.getTask(
            StringWriter() as Writer,
            null,
            diagnostics,
            listOf("-source", "17", "-target", "17"),
            null,
            listOf<JavaFileObject>(sourceFile, classFile)
        )

        val success = task.call()

        val warnings = diagnostics.diagnostics
            .filter { it.kind == Diagnostic.Kind.WARNING }
            .map { it.getMessage(null) }

        if (!success) {
            val errors = diagnostics.diagnostics
                .filter { it.kind == Diagnostic.Kind.ERROR }
                .map { "${it.lineNumber}: ${it.getMessage(null)}" }
            throw CompilationException("Compilation failed:\n${errors.joinToString("\n")}")
        }

        val classBytes = classFile.getBytes()
        return CompiledScript(className, classBytes, warnings)
    }

    private fun compileKotlin(
        source: String,
        className: String,
        additionalDependencies: List<URL>
    ): CompiledScript {
        val compiler = kotlinCompiler
            ?: throw CompilationException("Kotlin compiler not initialized")

        val tempDir = Files.createTempDirectory("akiba_script")
        try {
            val sourceFile = tempDir.resolve("$className.kt")
            Files.writeString(sourceFile, source)

            val classPath = getClassPathUrls(additionalDependencies)
            val args = listOf(
                "-Xjdk-release=17",
                "-cp", classPath.joinToString(java.io.File.pathSeparator),
                sourceFile.toAbsolutePath().toString()
            )

            val result = invokeKotlinCompiler(compiler, args)
            if (!result) {
                throw CompilationException("Kotlin compilation failed")
            }

            val classFile = tempDir.resolve("$className.class")
            if (!Files.exists(classFile)) {
                throw CompilationException("Kotlin compilation did not produce class file")
            }

            val classBytes = Files.readAllBytes(classFile)
            return CompiledScript(className, classBytes)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    private fun invokeKotlinCompiler(compiler: Any, args: List<String>): Boolean {
        val method = kotlinCompilerClass?.java?.getMethod("compile", List::class.java)
        val result = method?.invoke(compiler, args)
        return result == true
    }

    private fun getClassPathUrls(additionalDependencies: List<URL>): List<String> {
        val urls = mutableListOf<String>()
        additionalDependencies.forEach { urls.add(it.path) }
        urls.add(System.getProperty("java.class.path"))
        return urls
    }

    fun validate(source: String): List<String> {
        val issues = mutableListOf<String>()

        if (source.isBlank()) {
            issues.add("Source code is empty")
            return issues
        }

        val hasClass = source.contains("class ")
        val hasInterface = source.contains("interface ")

        if (!hasClass && !hasInterface) {
            issues.add("Source must contain a class or interface definition")
        }

        return issues
    }
}

class CompilationException(message: String) : Exception(message)