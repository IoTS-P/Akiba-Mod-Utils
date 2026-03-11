plugins {
    kotlin("jvm") version "2.1.20"
    kotlin("plugin.serialization") version "2.1.20"
}

group = "org.iotsplab.akiba"   // Change this to your own group

repositories {
    mavenCentral()
}

val PublicConfiguration by configurations.register("Public")

/***********************************************************************************************************************
 * MODULE DEFINITION START, DO NOT CHANGE CODES OUTSIDE THIS BLOCK
***********************************************************************************************************************/

val modNames: Map<String, String> = mapOf(
    "AkibaUtils" to "1.0"
)

val underDevelopmentModules: List<String> = listOf()

val mods = modNames.keys.associate {
    it to configurations.register(it)
}

dependencies {
    PublicConfiguration(project(":akiba_framework"))
}

val finalizeTasks: Map<String, Jar.() -> Unit> = mapOf()

/***********************************************************************************************************************
 * MODULE DEFINITION END
***********************************************************************************************************************/

fun moduleDependency(modules: List<String>): ConfigurableFileCollection {
    return files(modules.map { "build/libs/amod-${it}-${modNames[it]}.jar" }.toTypedArray())
}

modNames.forEach { moduleName, ver ->
    val globalGroup = group

    configurations[moduleName].extendsFrom(configurations["Public"])

    sourceSets.create(moduleName) {
        kotlin.srcDir("src/${moduleName}/kotlin")

        compileClasspath += configurations[moduleName]
        runtimeClasspath += configurations[moduleName]
    }

    // Exclude modules that are under development
    if (!underDevelopmentModules.contains(moduleName)) {
        tasks.register<Jar>("moduleJar-$moduleName") {
            group = globalGroup as String
            archiveBaseName.set("amod-$moduleName")
            archiveVersion.set(ver)

            duplicatesStrategy = DuplicatesStrategy.EXCLUDE

            from(sourceSets[moduleName].output) {
                duplicatesStrategy = DuplicatesStrategy.EXCLUDE
            }

            // Pack all jars except Akiba and Ghidra
            from(
                configurations[moduleName].resolve()
                    .filter {
                        it.name.endsWith("jar") &&
                                // exclude all common jar
                                !configurations["Public"].contains(it) &&
                                !it.name.startsWith("amod")
                    }
                    .map { zipTree(it) }
            ) {
                duplicatesStrategy = DuplicatesStrategy.EXCLUDE
            }

            exclude("META-INF/*.RSA", "META-INF/*.SF", "META-INF/*.DSA", "**/.*/**")

            // Write dependency class names into 'META-INF/module-deps'
            val dependencyClassNames = configurations[moduleName].resolve()
                .filter { it.name.startsWith("amod") }
                .map { group + "." + it.name.substringAfter("amod-").substringBefore("-") }
            val depFile = temporaryDir.resolve("META-INF/module-deps")
            depFile.parentFile.mkdirs()
            depFile.writeText(dependencyClassNames.joinToString("\n"))
            from(depFile) { into("META-INF") }

            manifest {
                attributes["Main-Class"] = "$group.$moduleName"
            }

            finalizeTasks[moduleName]?.invoke(this)
        }
    }
}

fun recDepend(allTask: Task, undone: MutableList<Task>, selected: Task) {
    val moduleName = selected.name.substringAfter("moduleJar-")
    val dependencies = configurations[moduleName].resolve()
        .filter { it.name.startsWith("amod") && !it.path.contains("/modules/") }
    if (dependencies.isEmpty()) {
        allTask.dependsOn(selected)
    } else {
        for (dependency in dependencies) {
            val dependencyName = dependency.name.substringAfter("amod-").substringBefore("-")
            val dependencyTask = tasks.getByName("moduleJar-$dependencyName")
            selected.mustRunAfter(dependencyTask)
            if (undone.contains(dependencyTask))
                recDepend(allTask, undone, dependencyTask)
        }
        allTask.dependsOn(selected)
    }
    undone.remove(selected)
}

tasks.register("moduleJar-ALL") {
    val undoneTasks = tasks.filter { it.name.startsWith("moduleJar-") && it.name != "moduleJar-ALL" }
        .toMutableList()
    while (!undoneTasks.isEmpty()) {
        val selected = undoneTasks.first()
        recDepend(this, undoneTasks, selected)
    }
}

tasks.register<Zip>("bundle-zip") {
    archiveBaseName.set("akiba_modules")
    archiveVersion.set(version.toString())
    description = "Bundle all akiba module JARs into one zip file"

    val libDir = layout.buildDirectory.dir("libs")
    destinationDirectory.set(libDir)

    from(libDir) {
        include("amod-*.jar")
        exclude("amod-Test*.jar")
    }
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(21)
}