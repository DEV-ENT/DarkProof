import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.zip.ZipInputStream

// DarkProof for desktop computers (Windows first). Run it with: ./gradlew -Pdesktop :desktop:run
//
// The parts of the Android app that use no Android code are compiled here as they are, straight from
// app/src/main/java, so the phone and the desktop run the same packet, encryption and forwarding code. Nothing is
// copied and no Android file is moved. Desktop-only code lives in src/main/kotlin/it/blackout/desktop.
plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.compose") version "1.12.2" // Compose Multiplatform: the Android screens' toolkit, on a desktop JVM
}

// Files of the Android app that the desktop compiles as they are. Most use no Android at all. The engine and the files
// around it (MeshEngine, NostrLink, Groups, EncKeys) call a few Android classes, which the desktop answers with
// stand-ins under Android's names (src/main/java/android) and with its own versions of the phone-only objects they
// name (src/main/kotlin/it/blackout/desktop/standin).
val shared = listOf(
    "App", "AppState", "BleProtocol", "Contact", "Core", "EncKeys", "Fingerprint", "Groups", "Help", "Hpke",
    "LockRules", "MeshCore", "MeshEngine", "MessageKeys", "Meshtastic", "Moderation", "Nostr", "NostrLink", "P256",
    "PlusCode", "Protocol", "QuickCheckIn", "Ready", "Schnorr", "ScreenRules", "Screens", "Scrypt", "Socks5",
    "Times", "Ui", "WifiLinks", "WordFilter",
)

// The Android app's unit tests: all of them run again here, on a desktop JVM with no Android.
val sharedTests = listOf(
    "AppLockFixTest", "AuthorshipTest", "BleProtocolTest", "CheckInExtrasTest", "CoreTest", "DoorStoreFixTest",
    "FaultTest", "FirstCopyTest", "FormatVectorsTest", "HpkeTest", "HybridTest", "InviteFixTest", "KeyChangesTest",
    "KeyringTest", "LinkLimitsFixTest", "MeshCoreTest", "MessageKeysTest", "MiscFixTest", "NostrTest",
    "PaddingTest", "PlusCodeTest", "PrivacyTest", "ProtocolTest", "RekeyTest", "RelayAttackTest", "RelayIntakeTest",
    "RelayLimitsFixTest", "RelayLinksTest", "SchnorrTest", "ScryptTest", "SharedVectorsTest", "StoredDataFixTest",
    "TestSigning", "WifiLinksTest", "WordFilterTest",
)

// The phone's pictures (app/src/main/res/drawable*) go on the desktop's classpath as they are, and the build writes an
// R like Android's that names them, so the phone's screens find their icons under the names they already use.
val phoneRes = layout.projectDirectory.dir("../app/src/main/res")
val generateR = tasks.register("generateR") {
    val dirs = listOf("drawable", "drawable-nodpi").map { phoneRes.dir(it) }
    val out = layout.buildDirectory.dir("generated/r")
    inputs.files(dirs); outputs.dir(out)
    doLast {
        val files = dirs.flatMap { d -> d.asFile.listFiles().orEmpty().filter { it.isFile }.map { "${d.asFile.name}/${it.name}" } }.sortedBy { it.substringAfter('/') }
        val f = out.get().file("it/blackout/desktop/standin/R.kt").asFile; f.parentFile.mkdirs()
        f.writeText(buildString {
            appendLine("package it.blackout.mesh"); appendLine()
            appendLine("/** Written by the build from app/src/main/res: the names Android's R gives the phone's pictures, and where each one is. */")
            appendLine("object R {")
            appendLine("    object drawable {")
            files.forEachIndexed { i, p -> appendLine("        const val ${p.substringAfter('/').substringBeforeLast('.')} = ${i + 1}") }
            appendLine("    }")
            appendLine("    private val paths = arrayOf(" + files.joinToString(", ") { "\"$it\"" } + ")")
            appendLine("    fun path(id: Int): String = paths[id - 1]")
            appendLine("}")
        })
    }
}
sourceSets.named("main") { resources { srcDir(phoneRes); include("drawable/**", "drawable-nodpi/**", "icon.png") } } // icon.png: the desktop's own, see icons/MakeIcon.java

kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
    sourceSets {
        named("main") {
            kotlin.srcDir(generateR)
            kotlin.srcDir("../app/src/main/java")
            kotlin.include(shared.map { "it/blackout/mesh/$it.kt" } + "it/blackout/desktop/**")
        }
        named("test") {
            kotlin.srcDir("../app/src/test/java")
            kotlin.include(sharedTests.map { "it/blackout/mesh/$it.kt" } + "it/blackout/desktop/**")
        }
    }
}
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }

// The Compose build for the computer this runs on. Written out instead of the plugin's `compose.desktop.currentOs`,
// whose sibling aliases (`compose.ui` and so on) are deprecated since Compose Multiplatform 1.10.
val composeTarget = run {
    val os = System.getProperty("os.name").lowercase(); val arch = System.getProperty("os.arch").lowercase()
    val name = when { "mac" in os -> "macos"; "win" in os -> "windows"; else -> "linux" }
    "$name-${if (arch == "aarch64" || arch == "arm64") "arm64" else "x64"}"
}

dependencies {
    implementation("org.jetbrains.compose.desktop:desktop-jvm-$composeTarget:1.12.2")
    implementation("org.jetbrains.compose.material3:material3:1.12.0-alpha03") // the Material 3 that Compose Multiplatform 1.12.2 lists
    implementation("org.bouncycastle:bcprov-jdk18on:1.80.2") // same version as the Android app
    implementation("org.json:json:20240303") // Android has org.json built in; a desktop JVM does not
    implementation("com.squareup.okhttp3:okhttp:4.12.0") // relay WebSockets, same version as the Android app
    implementation("org.xerial:sqlite-jdbc:3.54.1.0") // SQLite for the message store (Android has its own); Apache 2.0, Windows, macOS and Linux builds inside
    implementation("com.google.zxing:core:3.5.3") // invite QR codes, same version as the Android app
    testImplementation("junit:junit:4.13.2")
}

// A failed test says why in the build's own output: on a build machine there is nothing else to look at.
tasks.withType<Test>().configureEach {
    testLogging { events("failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}

// The AI engine: llama.cpp's own server program (MIT), one pinned build from its authors' releases, checked by SHA-256
// before it is unpacked. It is code from outside, so it is fetched only when asked for with -PaiEngine (the build on
// GitHub asks). Without it the app builds and runs, and its Ask page says this copy has no AI engine.
val aiEngineBuild = "b12590"
val aiEngines = mapOf( // the computer it is for, to the file's name and SHA-256
    "windows-x64" to ("llama-$aiEngineBuild-bin-win-cpu-x64.zip" to "e895687489ceed01770fd5101ac377ad77ed41b5b2b7dafc8e1e1bfca613ba62"),
    "macos-arm64" to ("llama-$aiEngineBuild-bin-macos-arm64.tar.gz" to "c0961e9c1ee87fb17357825a8f4a0a294ce7334093e1295917f71f17977d5ad6"),
)
val engineRoot = layout.projectDirectory.dir("engine") // engine/<computer>/llama goes into the app as resources/llama
val fetchAiEngine = tasks.register("fetchAiEngine") {
    val wanted = providers.gradleProperty("aiEngine").isPresent
    val pick = aiEngines[composeTarget]
    val into = engineRoot.dir("$composeTarget/llama").asFile
    val work = layout.buildDirectory.dir("ai-engine").get().asFile
    onlyIf { wanted && pick != null }
    doLast {
        val (name, sha) = pick!!
        fun sha256(f: File): String {
            val md = MessageDigest.getInstance("SHA-256")
            f.inputStream().use { i -> val b = ByteArray(1 shl 16); while (true) { val n = i.read(b); if (n < 0) break; md.update(b, 0, n) } }
            return md.digest().joinToString("") { "%02x".format(it) }
        }
        val archive = File(work, name)
        if (!archive.isFile || sha256(archive) != sha) {
            work.mkdirs()
            uri("https://github.com/ggml-org/llama.cpp/releases/download/$aiEngineBuild/$name").toURL().openStream().use { i -> archive.outputStream().use { i.copyTo(it) } }
        }
        check(sha256(archive) == sha) { "$name is not the file that was pinned (SHA-256 ${sha256(archive)})" }
        val unpacked = File(work, "unpacked"); unpacked.deleteRecursively(); unpacked.mkdirs()
        if (name.endsWith(".zip")) { // read here: what "tar" is on a Windows computer depends on what else is installed
            ZipInputStream(archive.inputStream()).use { zip ->
                while (true) {
                    val e = zip.nextEntry ?: break
                    val out = File(unpacked, e.name).canonicalFile
                    check(out.path.startsWith(unpacked.canonicalPath + File.separator)) { "$name holds a file that would land outside its folder: ${e.name}" }
                    if (e.isDirectory) out.mkdirs() else { out.parentFile.mkdirs(); out.outputStream().use { zip.copyTo(it) } }
                }
            }
        } else {
            val tar = ProcessBuilder("tar", "-xzf", archive.path, "-C", unpacked.path).inheritIO().start()
            check(tar.waitFor() == 0) { "could not unpack $name" }
        }
        val server = unpacked.walkTopDown().firstOrNull { it.name == "llama-server" || it.name == "llama-server.exe" } ?: error("no llama-server in $name")
        into.deleteRecursively(); into.mkdirs()
        // The server, the libraries beside it and the licences; not the other programs of the archive.
        val wantedFile = Regex("""(llama-server(\.exe)?|.*\.(dll|dylib|so)(\.\d+)*|LICENSE.*)""")
        (server.parentFile.listFiles().orEmpty().toList() + unpacked.walkTopDown().filter { it.name.startsWith("LICENSE") }).distinct()
            .filter { it.name.matches(wantedFile) && Files.isRegularFile(it.toPath()) } // a link to a library is copied as the library
            .forEach { f -> val out = File(into, f.name); Files.copy(f.toPath(), out.toPath(), StandardCopyOption.REPLACE_EXISTING); if (f.canExecute() || f.name.startsWith("llama-server")) out.setExecutable(true) }
        check(File(into, server.name).isFile) { "the AI engine was not unpacked" }
    }
}
tasks.matching { it.name == "prepareAppResources" }.configureEach { dependsOn(fetchAiEngine) }

compose.desktop {
    application {
        mainClass = "it.blackout.desktop.MainKt"
        // The app calls into the system itself: Windows for a dark title bar (TitleBar.kt), and the database's own library.
        // Java asks to be told so, and later versions will refuse without it.
        jvmArgs += "--enable-native-access=ALL-UNNAMED"
        // The installer. It has to be built on the system it is for: .github/workflows/desktop-windows.yml builds the
        // Windows one on GitHub. It is not signed, so Windows warns before running it.
        nativeDistributions {
            appResourcesRootDir.set(engineRoot) // the AI engine and its notice (above)
            targetFormats(org.jetbrains.compose.desktop.application.dsl.TargetFormat.Msi)
            packageName = "DarkProof"
            packageVersion = "0.4.1" // the Android app's versionName (app/build.gradle.kts); Windows wants three numbers
            description = "DarkProof: messages when there is no internet"
            vendor = "DarkProof"
            includeAllModules = true // the whole Java runtime: a trimmed one leaves out parts the encryption and the database need
            windows {
                menuGroup = "DarkProof"; shortcut = true
                iconFile.set(project.file("icons/DarkProof.ico")) // the program's and its shortcuts' icon, drawn by icons/MakeIcon.java
                perUserInstall = true // installs for the person, with no administrator password
                upgradeUuid = "47564acc-4ff5-4925-be87-f8f7e3a80ba7" // never change: it is how a newer installer finds and replaces an older DarkProof
            }
        }
    }
}
