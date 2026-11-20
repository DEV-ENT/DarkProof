package it.blackout.desktop

import it.blackout.mesh.Groups
import it.blackout.mesh.Invite
import it.blackout.mesh.MeshEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The desktop app used the way a person uses it, by a script: it reads the phones' own screens, taps what is written
 * on them and types into their fields ([Screen]), and checks both what the screen then says and what the engine
 * underneath did. The first setup ("Create a group") is scripted too, in [RealEngine]. Pictures of the screens it
 * passes are left in build/screen-*.png for a look.
 */
class WindowScriptTest {
    @Test fun aPersonCanUseTheApp() {
        RealEngine.started(); val a = RealEngine.activity; val c = a // the app's one Context
        val peer = EveryonePeer("Anna", loopback = true)
        Screen { App(a) }.use { s ->
            try {
                // Home, after the scripted setup
                a.state.tab = 0; a.state.sheet = null; s.settle()
                assertTrue(s.has("My group") && s.has("Looking for phones")); assertEquals("My group", Groups.current(c)!!.name)
                // A computer's words, and none of the steps only a phone can do
                assertTrue(s.has("Your messages wait on this computer") && s.has("DarkProof looks for phones while it is open."))
                assertTrue(s.has("Invite your people") && s.has("Try a practice run"))
                for (phoneOnly in listOf("Save the map of your area", "Add the “I'm safe” tile", "Turn on notifications", "Download the offline AI", "also when the app is closed")) assertFalse(phoneOnly, s.has(phoneOnly))
                s.png("build/screen-home.png")

                // The invite sheet: a QR code, a link to share, and the emoji to compare
                s.tap("Invite"); assertTrue(s.has("Invite to My group") && s.has("Invite QR code") && s.has("Share invite link") && s.has("Show code"))
                assertFalse(s.has("Share the app")) // only an Android phone can send the Android app
                // no picture of this sheet: its QR code is the group's code
                s.tap("Share invite link") // a phone opens its share sheet; a computer copies it
                s.await("the note that the link was copied") { s.has("Copied. Paste it where you want to send it.") }
                s.tap("Close")

                // A message to the group
                s.tap("Chat"); assertTrue(s.has("Only people in My group can read these"))
                s.type("Message My group", "Hello from the window"); s.tap("Send")
                s.await("the group message in the engine") { MeshEngine.snapshot().any { it.text == "Hello from the window" && !it.public && it.sender == MeshEngine.deviceId } }
                s.await("the group message on the screen") { s.has("Hello from the window") }
                s.png("build/screen-chat-group.png")

                // A message to Everyone
                s.tap("Everyone"); assertTrue(s.has("Anyone with DarkProof can read these"))
                s.type("Message everyone", "Hello everyone, from the window"); s.tap("Send")
                s.await("the Everyone message in the engine") { MeshEngine.snapshotAll().any { it.text == "Hello everyone, from the window" && it.public } }

                // Connections: link to another device by typing its address, as on a network where phones don't find each other
                s.tap("Home"); s.tap("Connect"); assertTrue(s.has("Connections") && s.has("Wi-Fi network") && s.has("Send through another app"))
                assertTrue(s.has("None linked")); for (phoneOnly in listOf("Searching", "Internet", "Through Tor", "Long-range radio", "Battery saver", "Wi-Fi board")) assertFalse(phoneOnly, s.says(phoneOnly))
                assertTrue(s.has("They keep working in a blackout.")); assertFalse(s.has("All but Internet"))
                s.png("build/screen-connections.png")
                s.tap("Nearby phones"); assertTrue(s.has("Same Wi-Fi network") && s.has("Looking on this network") && s.has("This computer: "))
                assertFalse(s.has("Bluetooth")); assertFalse(s.has("This phone"))
                s.type("192.168.1.20:7777", "not an address"); s.tap("Connect")
                s.await("the note about a wrong address") { s.has("Type it as address:port") }
                s.type("not an address", "127.0.0.1:${peer.start(0)}"); s.tap("Connect")
                s.await("the link") { peer.wifi.linkCount() == 1 && MeshEngine.linkedNodes().size == 1 }
                s.await("the screen to say so") { s.has("1 phone linked over Wi-Fi") }
                s.tap("Close"); s.await("Home to count it") { s.has("Connected") }

                // What the other device posts shows up, signed; what was posted here before the link reached it
                peer.send("Is anyone near the station?")
                s.tap("Chat"); s.await("the other device's post on the screen") { s.has("Is anyone near the station?") && s.has("Anna") }
                RealEngine.await("this computer's earlier post at the other device") { peer.lines().any { it.text == "Hello everyone, from the window" && it.name == "Desktop" && it.verified } }
                s.png("build/screen-chat-everyone.png")

                // "I'm safe"
                s.tap("People"); s.tap("I'm safe")
                s.await("the check-in on the screen") { s.has("Your last check-in: safe, just now.") }
                assertTrue(MeshEngine.snapshot().count { !it.public && it.sender == MeshEngine.deviceId } >= 2) // the message and the check-in
                s.png("build/screen-people.png")

                // The other tabs open
                s.tap("Places"); assertTrue(s.has("Share a place") && s.has("Nothing shared yet")); assertFalse(s.has("Map")); s.png("build/screen-places.png")
                s.tap("Ask"); assertTrue(s.has("The AI isn't on the desktop yet")); s.png("build/screen-ask.png")

                // Settings: a new name
                s.tap("Home"); s.tap("Settings"); assertTrue(s.has("Your name") && s.has("Groups") && s.has("Help and privacy"))
                for (phoneOnly in listOf("Notifications", "Lock DarkProof", "Share the app", "Share my location", "this phone")) assertFalse(phoneOnly, s.has(phoneOnly))
                s.png("build/screen-settings.png")
                s.tap("Your name"); s.type("Desktop", "Dana"); s.tap("Save")
                s.await("the new name in the engine") { MeshEngine.name == "Dana" }
                assertEquals("Dana", c.getSharedPreferences("mesh", 0).getString("name", null))
                s.tap("Your name"); s.type("Dana", "Desktop"); s.tap("Save"); s.await("the old name back") { MeshEngine.name == "Desktop" }
                s.tap("Close")

                // Another group, joined with a code someone told us: it is saved and shown, and waits to be let in
                val mine = Groups.current(c)!!; val code = Invite.newCode()
                s.tap("Switch group"); assertTrue(s.has("In use")); s.tap("Join or start another group"); s.tap("Join a group")
                assertTrue(s.has("Type the code your friend tells you, or paste the invite link they send.")); assertFalse(s.has("Scan"))
                s.typeInto(0, code); s.typeInto(1, "Neighbours"); s.tap("Join")
                s.await("the new group in use") { Groups.current(c)?.code == code && MeshEngine.currentCode == code }
                assertEquals("Neighbours", Groups.current(c)!!.name); assertTrue(MeshEngine.joining(code))
                s.settle(); assertTrue(s.has("Neighbours")); assertFalse(s.has(code))
                s.png("build/screen-joining.png")
                // …and back to the first group
                s.tap("Switch group"); assertTrue(s.has("Your other groups") && s.has("My group")); s.tap("Switch")
                s.await("the first group in use again") { Groups.current(c)?.code == mine.code && MeshEngine.currentCode == mine.code }
            } finally { a.state.tab = 0; a.state.sheet = null; MeshEngine.wifi?.links?.stopManual(); peer.stop() }
        }
    }
}
