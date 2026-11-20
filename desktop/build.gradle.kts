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
sourceSets.named("main") { resources { srcDir(phoneRes); include("drawable/**", "drawable-nodpi/**") } }

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

compose.desktop {
    application {
        mainClass = "it.blackout.desktop.MainKt"
        // The installer. It has to be built on the system it is for: .github/workflows/desktop-windows.yml builds the
        // Windows one on GitHub. It is not signed, so Windows warns before running it.
        nativeDistributions {
            targetFormats(org.jetbrains.compose.desktop.application.dsl.TargetFormat.Msi)
            packageName = "DarkProof"
            packageVersion = "0.4.1" // the Android app's versionName (app/build.gradle.kts); Windows wants three numbers
            description = "DarkProof: messages when there is no internet"
            vendor = "DarkProof"
            includeAllModules = true // the whole Java runtime: a trimmed one leaves out parts the encryption and the database need
            windows {
                menuGroup = "DarkProof"; shortcut = true
                perUserInstall = true // installs for the person, with no administrator password
                upgradeUuid = "47564acc-4ff5-4925-be87-f8f7e3a80ba7" // never change: it is how a newer installer finds and replaces an older DarkProof
            }
        }
    }
}
