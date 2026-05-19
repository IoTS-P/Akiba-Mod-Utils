package org.iotsplab.akiba.module.server.script

import java.io.File
import java.net.URL
import java.net.URLClassLoader
import java.security.ProtectionDomain

/**
 * ClassLoader for dynamically loading and executing scripts.
 * Uses the current process's classpath and allows loading additional JARs.
 */
class ScriptClassLoader(
    private val parentLoader: ClassLoader,
    private val additionalJars: List<File> = emptyList()
) : ClassLoader(parentLoader) {

    private val loadedClasses = mutableMapOf<String, Class<*>>()

    @Suppress("UNCHECKED_CAST")
    fun loadScript(compiledScript: CompiledScript): Class<out AkibaScript> {
        val className = compiledScript.className

        if (loadedClasses.containsKey(className)) {
            return loadedClasses[className] as Class<out AkibaScript>
        }

        val definedClass = defineClass(
            className,
            compiledScript.classBytes,
            0,
            compiledScript.classBytes.size,
            ProtectionDomain(null, null)
        ) as Class<out AkibaScript>

        loadedClasses[className] = definedClass
        return definedClass
    }

    fun compileAndLoad(source: String, className: String): Class<out AkibaScript> {
        val compiled = ScriptCompiler.compile(source, className, additionalJars.map { it.toURI().toURL() })
        return loadScript(compiled)
    }

    @Suppress("UNCHECKED_CAST")
    fun instantiateScript(
        scriptClass: Class<out AkibaScript>,
        binaryId: Int,
        program: ghidra.program.model.listing.Program?
    ): AkibaScript {
        val constructor = scriptClass.constructors.find { c ->
            c.parameterCount == 0 || (c.parameterCount == 1 && c.parameters[0].type == Int::class.java)
        } ?: throw IllegalStateException("No suitable constructor found for script class")

        return if (constructor.parameterCount == 0) {
            constructor.newInstance() as AkibaScript
        } else {
            constructor.newInstance(binaryId) as AkibaScript
        }.apply {
            if (program != null) {
                val field = scriptClass.superclass.getDeclaredField("program")
                field.isAccessible = true
                field.set(this, program)
            }
        }
    }

    fun loadJar(file: File): ScriptClassLoader {
        if (!file.exists()) {
            throw IllegalArgumentException("JAR file does not exist: ${file.absolutePath}")
        }
        if (!file.name.endsWith(".jar")) {
            throw IllegalArgumentException("File is not a JAR: ${file.name}")
        }
        val newAdditionalJars = additionalJars + file
        return ScriptClassLoader(parentLoader, newAdditionalJars)
    }

    fun getLoadedJars(): List<File> = additionalJars.toList()

    companion object {
        fun createWithFrameworkAccess(): ScriptClassLoader {
            val frameworkLoader = AkibaScript::class.java.classLoader
            return ScriptClassLoader(frameworkLoader, emptyList())
        }

        fun createWithDependencies(jars: List<File>): ScriptClassLoader {
            val frameworkLoader = AkibaScript::class.java.classLoader
            return ScriptClassLoader(frameworkLoader, jars)
        }
    }
}