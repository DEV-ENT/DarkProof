package it.blackout.desktop

import it.blackout.mesh.Invite
import it.blackout.mesh.MeshEngine
import it.blackout.mesh.SavedGroup
import it.blackout.mesh.WifiLink
import java.io.File

/**
 * `DarkProof --self-test`: starts the engine without a window in the data folder (set DARKPROOF_HOME to a throwaway
 * one: a folder already in use is refused), makes a group, writes to it and to Everyone, and checks they are kept. It shows that a built app has what the
 * engine needs on this computer: the encryption, the database and the network link. The result is the exit code (0 is
 * good) and a file self-test.txt in the data folder, since a built Windows app has no console to print to.
 */
object SelfTest {
    fun run(): Int {
        val out = StringBuilder()
        fun say(s: String) { out.appendLine(s); println(s) }
        val ok = runCatching {
            WifiLink.discovery = null // a self-test's messages are not for real devices: it neither looks for them nor announces itself
            val a = Desktop.activity()
            check(a.state.group == null) { "this data folder is in use: set DARKPROOF_HOME to an empty folder" } // never a test group in someone's real DarkProof
            say("data folder ready on ${System.getProperty("os.name")} ${System.getProperty("os.arch")}, Java ${System.getProperty("java.version")}")
            val code = Invite.newCode()
            MeshEngine.found(a, code); a.started("Self test", SavedGroup("Self test", code))
            await("the engine to start") { MeshEngine.router != null }; say("engine started: keys made, database open")
            await("the group's first key") { !MeshEngine.joining(code) }
            MeshEngine.send("group message"); MeshEngine.send("everyone message", public = true)
            await("both messages to be kept") { MeshEngine.snapshotAll().count { it.sender == MeshEngine.deviceId } == 2 }; say("a group message and an Everyone message sealed, signed and kept")
            await("the network link to listen") { (MeshEngine.wifi?.links?.port ?: 0) > 0 }; say("listening for phones on port ${MeshEngine.wifi?.links?.port}")
            MeshEngine.shutdown()
        }.onFailure { say("FAILED: $it"); it.stackTrace.take(12).forEach { l -> say("    at $l") } }.isSuccess
        say(if (ok) "SELF-TEST OK" else "SELF-TEST FAILED")
        runCatching { File(Home.folder(), "self-test.txt").writeText(out.toString()) }
        return if (ok) 0 else 1
    }

    private fun await(what: String, ok: () -> Boolean) {
        val end = System.currentTimeMillis() + 30_000
        while (!ok()) { check(System.currentTimeMillis() < end) { "timed out waiting for $what" }; Thread.sleep(50) }
    }
}
