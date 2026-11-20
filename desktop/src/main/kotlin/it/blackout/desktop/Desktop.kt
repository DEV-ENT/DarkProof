package it.blackout.desktop

import it.blackout.mesh.AppState
import it.blackout.mesh.Groups
import it.blackout.mesh.MainActivity
import it.blackout.mesh.MeshEngine
import it.blackout.mesh.Notifier
import java.io.File

/** What the desktop app does where a phone's activity starts up: the same steps, without the phone-only ones. */
object Desktop {
    /**
     * Makes what the phones' screens are handed (their "activity" and its state) and starts the engine if a group is
     * saved; before the first setup the screens ask for a name and a group, as on a phone.
     *
     * Internet relays start switched off: the phones reach them through Tor inside the app, which the desktop doesn't
     * have yet.
     */
    fun activity(dir: File = Home.folder()): MainActivity {
        val a = MainActivity(dir); Home.set(a)
        val prefs = a.getSharedPreferences("mesh", 0)
        if (!prefs.contains("internet")) prefs.edit().putBoolean("internet", false).commit()
        a.state = AppState(a)
        MeshEngine.listener = { Groups.current(a)?.let { if (it != a.state.group) a.state.group = it }; a.state.tick++ } // a removal changes the group's code
        Notifier.onScreen = true; Notifier.inApp = { a.state.banner = it }
        a.startStore()
        return a
    }
}
