package it.blackout.mesh

import android.content.Context
import android.os.Handler
import android.os.Looper
import it.blackout.desktop.Mdns
import org.json.JSONObject

// The desktop's versions of phone-only objects that the phone's engine names (same names and calls), so that it
// compiles for the desktop unchanged. Each says what it stands in for and what is still missing.

/** The phones' debug builds have test hooks here; the desktop only logs (shown with DARKPROOF_DEBUG=1). */
object DebugTools {
    const val ahead = 0L
    fun relays(c: Context): List<String>? = null
    fun log(s: String) { android.util.Log.i("DarkProof", s) }
    fun noteCode(code: String?) {}
}

/**
 * "Connect through Tor". There is no Tor inside the desktop app yet, so its port is never ready: while the setting is
 * on (the default), the relay links wait and nothing goes to the internet relays.
 */
object Tor {
    const val CHECK_URL = "https://check.torproject.org/api/ip"
    private fun prefs(c: Context) = c.getSharedPreferences("mesh", 0)
    fun enabled(c: Context) = prefs(c).getBoolean("tor", true)
    fun setEnabled(c: Context, on: Boolean) = prefs(c).edit().putBoolean("tor", on).apply()
    fun start(c: Context) {}
    fun stop(c: Context) {}
    fun socksPort(): Int? = null
    /** The Tor Project's answer: {"IsTor": true, "IP": …}. The same check as the phones'. */
    fun isTor(json: String): Boolean = runCatching { JSONObject(json).getBoolean("IsTor") }.getOrDefault(false)
    fun check(client: okhttp3.OkHttpClient, label: String = ""): Boolean = false
}

/**
 * DarkProof devices on the same network, found with DNS-SD and linked with [WifiLinks]: the desktop's version of the
 * phones' WifiLink.kt, with the desktop's own finder ([Mdns]) where a phone asks its system. The rules are the phones'
 * (spec/FORMAT.md, "Wi-Fi networks"): only the device with the smaller node id connects, it tries again every 10 s
 * while there is no link, and at most 256 found devices are remembered. An address can still be typed.
 */
class WifiLink(c: Context, private val nodeId: String, router: () -> MeshRouter?, changed: () -> Unit) {
    companion object {
        const val SERVICE = Mdns.SERVICE
        /**
         * The service type devices are looked for and announced under, or null to do neither. Tests and the self-test
         * set null, or a type of their own: what they write must never reach real DarkProof devices on the network.
         */
        @Volatile internal var discovery: String? = SERVICE
    }
    // DARKPROOF_DEBUG=1 also takes links from this computer itself, as the phones' debug builds do (emulator tests).
    private val debug = System.getenv("DARKPROOF_DEBUG") == "1"
    val links = WifiLinks(nodeId, router, changed) { WifiLinks.onLan(it) || (debug && it.isLoopbackAddress) }
    private val h = Handler(Looper.getMainLooper())
    private val found = HashMap<String, Pair<String, Int>>() // node id -> host, port (main thread)
    private var finder: Mdns? = null
    var running = false; private set

    fun start() {
        if (running) return
        running = true
        val port = links.listen()
        if (port == 0) return
        val type = discovery ?: return
        finder = Mdns(nodeId, port, found = { node, host, p -> h.post { onFound(node, host, p) } }, gone = { node -> h.post { found.remove(node) } }, type = type).also { it.start() }
        h.postDelayed(::retry, 10_000)
    }

    fun stop() {
        if (!running) return
        running = false
        h.removeCallbacksAndMessages(null)
        finder?.stop(); finder = null
        found.clear()
        links.stop()
    }

    /** Only the smaller node id connects (spec), and not to itself. */
    private fun wanted(node: String) = node != nodeId && nodeId < node

    private fun onFound(node: String, host: String, port: Int) {
        if (!running || !wanted(node) || (found.size >= LinkLimits.FOUND && node !in found)) return
        found[node] = host to port
        if (!links.linkedAt(node, host)) links.dial(host, port)
    }

    /** Every 10 s, dials the devices it found that have no link. Only a link to the address it would dial counts: one from elsewhere may only claim that device's node id. */
    private fun retry() {
        if (!running) return
        found.filter { (node, at) -> wanted(node) && !links.linkedAt(node, at.first) }.values.shuffled().forEach { (host, port) -> links.dial(host, port) }
        h.postDelayed(::retry, 10_000)
    }
}

/** LoRa radios reach a phone over Bluetooth. Not on the desktop yet: none is ever made here, the engine and the screens only need the names. */
class LoraLink private constructor() {
    companion object { const val PEER = "lora" }
    val status = "no radio"; val connected = false; val paired = false
    fun offer(p: Packet, mine: Boolean = false) {}
    fun scan(found: (addr: String, name: String) -> Unit) {}
    fun select(a: String) {}
    fun forget() {}
}

class MeshCoreLink private constructor() {
    companion object { const val PEER = "meshcore" }
    val status = "no radio"; val connected = false; val paired = false
    fun offer(p: Packet, mine: Boolean = false) {}
    fun scan(found: (addr: String, name: String) -> Unit) {}
    fun select(a: String) {}
    fun forget() {}
}

/** Bluetooth links to phones. Not on the desktop yet. */
class BleLink private constructor() {
    companion object { const val PREFIX = "ble:"; fun owns(peer: String) = peer.startsWith(PREFIX) }
    fun setSaver(on: Boolean) {}
    fun nodes(): Set<String> = emptySet()
    fun statusLine() = "Bluetooth: not on the desktop yet"
}

/** The phones' notifications and in-app alerts. The desktop shows none yet. */
object Notifier {
    @Volatile var onScreen = false
    var inApp: ((Alert) -> Unit)? = null
    data class Alert(val title: String, val body: String, val group: String?, val urgent: Boolean, val ask: Boolean, val messageId: String)
    fun forget(c: Context, ids: Collection<String>) {}
}
