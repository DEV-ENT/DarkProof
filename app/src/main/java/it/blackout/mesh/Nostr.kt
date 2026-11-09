package it.blackout.mesh

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64

/**
 * DarkProof packets as Nostr events on public relays (spec/FORMAT.md, "Internet relays"). Pure functions, so unit
 * tests run; [NostrLink] does the WebSockets. Each phone signs with a throwaway key made at every start.
 */
object Nostr {
    const val KIND = 3871  // a regular (stored) kind no one else uses (relay survey, 2026-11); see spec
    const val TAG_PREFIX = "dp1-"
    const val KEEP_S = 7 * 24 * 3600L    // relays may delete events after 7 days (NIP-40 expiration)

    fun tag(mailbox: Int) = TAG_PREFIX + "%04x".format(mailbox and 0xFFFF)

    /** NIP-01 string escaping, for computing event ids exactly as relays do. */
    fun quote(s: String): String = buildString {
        append('"')
        for (ch in s) when (ch) {
            '"' -> append("\\\""); '\\' -> append("\\\\"); '\n' -> append("\\n"); '\r' -> append("\\r")
            '\t' -> append("\\t"); '\b' -> append("\\b"); '\u000C' -> append("\\f")
            else -> if (ch < ' ') append("\\u%04x".format(ch.code)) else append(ch)
        }
        append('"')
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** The event id: SHA-256 of [0, pubkey, created_at, kind, tags, content] serialized as NIP-01 says. */
    fun eventId(pubkey: String, createdAt: Long, kind: Int, tags: List<List<String>>, content: String): String {
        val t = tags.joinToString(",", "[", "]") { tag -> tag.joinToString(",", "[", "]") { quote(it) } }
        val ser = "[0,${quote(pubkey)},$createdAt,$kind,$t,${quote(content)}]"
        return hex(MessageDigest.getInstance("SHA-256").digest(ser.toByteArray(Charsets.UTF_8)))
    }

    /** A signed event carrying one packet in the packet's mailbox, findable by packet id, kept by relays for 7 days. */
    fun event(p: Packet, secret: ByteArray, now: Long = System.currentTimeMillis() / 1000, aux: ByteArray? = null): JSONObject {
        val pub = hex(Schnorr.publicKey(secret))
        val tags = listOf(listOf("t", tag(Packet.mailbox(p.id))), listOf("x", p.id), listOf("expiration", (now + KEEP_S).toString()))
        val content = Base64.getEncoder().encodeToString(p.encode())
        val id = eventId(pub, now, KIND, tags, content)
        val sig = if (aux == null) Schnorr.sign(secret, unhex(id)) else Schnorr.sign(secret, unhex(id), aux)
        return JSONObject().put("id", id).put("pubkey", pub).put("created_at", now).put("kind", KIND)
            .put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", content).put("sig", hex(sig))
    }

    fun publish(event: JSONObject) = JSONArray().put("EVENT").put(event).toString()

    /** The Public channel's mailbox (spec/FORMAT.md, "Mailboxes"): worldwide, so it is caught up one page only. */
    const val PUBLIC_MAILBOX = 0x9576
    const val PAGE = 500                 // events per catch-up REQ
    const val MAX_PAGES = 4              // pages per group mailbox and relay link
    const val SINCE_MARGIN_S = 1_500L    // catch-up starts 25 min before the last time seen: events are dated up to 17 min back, and clocks differ
    /** An event's date: the current time, rounded down to about 17 minutes, so stored events don't give away when they were sent. */
    fun blurred(now: Long) = now - now % 1024
    const val RELAY_PER_MINUTE = 6_000   // messages taken from one relay link in a minute (100 a second)

    /**
     * New events for all these mailboxes, as they arrive. `since` 7 days back so events from phones with a slow clock
     * still match; `limit` 1 because stored events come from the catch-up REQs.
     */
    fun live(subId: String, mailboxes: Collection<Int>, now: Long = System.currentTimeMillis() / 1000): String =
        JSONArray().put("REQ").put(subId).put(JSONObject().put("kinds", JSONArray().put(KIND))
            .put("#t", JSONArray(mailboxes.map(::tag))).put("since", now - KEEP_S).put("limit", 1)).toString()

    /** One catch-up page of one mailbox: the newest [PAGE] events since [since], and not newer than [until] if set. */
    fun catchUp(subId: String, mailbox: Int, since: Long, until: Long?): String {
        val f = JSONObject().put("kinds", JSONArray().put(KIND)).put("#t", JSONArray().put(tag(mailbox))).put("since", since)
        if (until != null) f.put("until", until)
        return JSONArray().put("REQ").put(subId).put(f.put("limit", PAGE)).toString()
    }

    /** Asks which of these packets the relay already has (by the "x" tag), before passing them on. */
    fun have(subId: String, packetIds: Collection<String>): String =
        JSONArray().put("REQ").put(subId).put(JSONObject().put("kinds", JSONArray().put(KIND))
            .put("#x", JSONArray(packetIds)).put("limit", packetIds.size)).toString()

    fun close(subId: String) = JSONArray().put("CLOSE").put(subId).toString()

    /** A relay's answer to an event: ["OK", event id, accepted, message]. "duplicate:" refusals count as accepted. */
    class Ok(val eventId: String, val accepted: Boolean, val reason: String)
    fun ok(text: String): Ok? = runCatching {
        val a = JSONArray(text)
        if (a.getString(0) != "OK" || a.length() < 3) return null
        val why = a.optString(3)
        Ok(a.getString(1), a.getBoolean(2) || why.lowercase().startsWith("duplicate"), why)
    }.getOrNull()

    /** The end of a subscription's stored events: ["EOSE", id] ([complete]) or ["CLOSED", id, reason] (not complete). */
    class End(val subId: String, val complete: Boolean)
    fun end(text: String): End? = runCatching {
        val a = JSONArray(text)
        when (a.getString(0)) { "EOSE" -> End(a.getString(1), true); "CLOSED" -> End(a.getString(1), false); else -> null }
    }.getOrNull()

    /**
     * What makes two copies of a packet the same packet on the relays: its timestamp and cipher (ttl changes on every
     * hop). First 16 bytes of SHA-256(ts as 8 bytes big-endian ‖ cipher), in hex.
     */
    fun digest(p: Packet): String = hex(MessageDigest.getInstance("SHA-256").run {
        update(java.nio.ByteBuffer.allocate(8).putLong(p.ts).array()); digest(p.cipher)
    }.copyOf(16))

    /** The reason, if this is a relay refusing an event (["OK", id, false, reason]); else null. */
    fun refusal(text: String): String? = runCatching {
        val a = JSONArray(text)
        if (a.getString(0) == "OK" && !a.getBoolean(2)) a.optString(3) else null
    }.getOrNull()

    /** A refusal that means "slow down": NIP-01's "rate-limited:" and "blocked:", and what relays really say
     *  ("rate limited", "banned: too many rate-limit violations"). */
    fun isThrottle(reason: String) = reason.lowercase().let { r -> listOf("rate", "banned", "blocked").any { r.startsWith(it) } }

    /** A NIP-56 report of the event that carried a Public message (kind 1984, type "spam"/"other"…). */
    fun report(eventId: String, eventPubkey: String, secret: ByteArray, now: Long = System.currentTimeMillis() / 1000): JSONObject {
        val pub = hex(Schnorr.publicKey(secret))
        val tags = listOf(listOf("e", eventId, "other"), listOf("p", eventPubkey))
        val id = eventId(pub, now, 1984, tags, "")
        return JSONObject().put("id", id).put("pubkey", pub).put("created_at", now).put("kind", 1984)
            .put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", "").put("sig", hex(Schnorr.sign(secret, unhex(id))))
    }

    /**
     * What a relay sent: a DarkProof packet (with the event id and author, for reports; its time and subscription, for
     * catching up), or null for anything else.
     */
    class Received(val packet: Packet, val eventId: String, val pubkey: String, val createdAt: Long = 0, val subId: String = "")
    fun received(text: String): Received? = runCatching {
        val a = JSONArray(text)
        if (a.getString(0) != "EVENT" || a.length() < 3) return null
        val e = a.getJSONObject(2)
        if (e.getInt("kind") != KIND) return null
        val raw = Base64.getDecoder().decode(e.getString("content"))
        val p = Packet.decode(raw) ?: return null
        if (e.optLong("created_at") < 0) return null // no event is from before 1970: a hostile relay
        Received(p, e.getString("id"), e.getString("pubkey"), e.optLong("created_at"), a.getString(1))
    }.getOrNull()
}

/**
 * Reads WebSocket frame headers as they arrive, and fails as soon as a message would be longer than [max], before its
 * bytes are kept. OkHttp puts a message together in memory however long it is, so one relay could send a message that
 * ends the app (the iPhone's URLSession has maximumMessageSize). For one reader at a time.
 */
class WsFrameGuard(private val max: Long = MAX) {
    companion object {
        const val MAX = 1L shl 20
        private const val MAX_HTTP = 512 * 1024 // OkHttp itself takes 256 KiB of headers: past this, the frames below were never reached
        private const val AT_START = 0; private const val AFTER_CR = 1; private const val IN_LINE = 2
    }
    private var upgraded = false
    private var httpBytes = 0; private var line = AT_START; private var firstLine = true; private val status = StringBuilder()
    private val head = ByteArray(14); private var have = 0
    private var skip = 0L; private var message = 0L; private var endsMessage = false

    /**
     * The HTTP answer, whose lines end with LF or CRLF as OkHttp reads them. Anything but 101 ends the link: a relay has
     * no reason to send 100 or 103 first, and two of those make OkHttp 4.12 throw on a thread where it ends the app.
     */
    private fun http(x: Int) {
        if (++httpBytes > MAX_HTTP) throw java.io.IOException("relay's HTTP answer is too long")
        if (firstLine && status.length < 16 && x != '\r'.code && x != '\n'.code) status.append(x.toChar())
        when {
            x == '\n'.code && line != IN_LINE -> { // an empty line: the end of the answer
                val s = status.toString()
                val code = if (s.startsWith("HTTP/1.") && s.length >= 12) s.substring(9, 12) else if (s.startsWith("ICY ") && s.length >= 7) s.substring(4, 7) else ""
                if (code != "101") throw java.io.IOException("relay didn't upgrade the link")
                upgraded = true
            }
            x == '\n'.code -> { line = AT_START; firstLine = false }
            x == '\r'.code && line == AT_START -> line = AFTER_CR
            else -> line = IN_LINE
        }
    }

    fun look(b: ByteArray, off: Int, n: Int) {
        var i = off; val end = off + n
        while (i < end) {
            if (!upgraded) { http(b[i++].toInt() and 0xFF); continue }
            if (skip > 0) {
                val s = minOf(skip, (end - i).toLong()); i += s.toInt(); skip -= s
                if (skip == 0L && endsMessage) message = 0
                continue
            }
            head[have++] = b[i++]
            if (have >= 2 && have == needed()) frame()
        }
    }

    private fun needed(): Int = 2 + (when (head[1].toInt() and 0x7F) { 126 -> 2; 127 -> 8; else -> 0 }) + (if (head[1].toInt() and 0x80 != 0) 4 else 0)

    private fun frame() {
        val len7 = head[1].toInt() and 0x7F
        val len = when (len7) {
            126 -> ((head[2].toLong() and 0xFF) shl 8) or (head[3].toLong() and 0xFF)
            127 -> (0 until 8).fold(0L) { v, k -> (v shl 8) or (head[2 + k].toLong() and 0xFF) }
            else -> len7.toLong()
        }
        if (len < 0) throw java.io.IOException("relay frame length is out of range")
        val data = (head[0].toInt() and 0x0F) < 8 // control frames can come in the middle of a message and aren't part of it
        if (data) {
            if (len > max - message) throw java.io.IOException("relay message is too long")
            message += len
        }
        endsMessage = data && (head[0].toInt() and 0x80) != 0
        have = 0; skip = len
        if (skip == 0L && endsMessage) message = 0
    }
}

/** Puts [WsFrameGuard] between the relay's socket and OkHttp: on the decrypted stream, so it can see the frames. */
object WsLimit {
    /** [plain]: ws://, only the mock relay of debug builds. There the guard goes on the plain socket, which with TLS would carry only encrypted bytes. */
    fun apply(b: okhttp3.OkHttpClient.Builder, plain: Boolean) {
        val tmf = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()).apply { init(null as java.security.KeyStore?) }
        val tm = tmf.trustManagers.filterIsInstance<javax.net.ssl.X509TrustManager>().first() // the phone's own trust store, as OkHttp's default
        val tls = javax.net.ssl.SSLContext.getInstance("TLS").apply { init(null, arrayOf(tm), null) }.socketFactory
        b.sslSocketFactory(GuardedTls(tls), tm)
        if (plain) b.socketFactory(GuardedPlain)
    }

    private class GuardedInput(s: java.io.InputStream) : java.io.FilterInputStream(s) {
        private val guard = WsFrameGuard()
        private val one = ByteArray(1)
        override fun read(): Int = if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xFF
        override fun read(b: ByteArray, off: Int, len: Int): Int { val n = super.read(b, off, len); if (n > 0) guard.look(b, off, n); return n }
    }

    private object GuardedPlain : javax.net.SocketFactory() {
        override fun createSocket(): java.net.Socket = object : java.net.Socket() {
            private val input by lazy { GuardedInput(super.getInputStream()) }
            override fun getInputStream(): java.io.InputStream = input
        }
        override fun createSocket(h: String, p: Int) = throw UnsupportedOperationException()
        override fun createSocket(h: String, p: Int, l: java.net.InetAddress, lp: Int) = throw UnsupportedOperationException()
        override fun createSocket(h: java.net.InetAddress, p: Int) = throw UnsupportedOperationException()
        override fun createSocket(h: java.net.InetAddress, p: Int, l: java.net.InetAddress, lp: Int) = throw UnsupportedOperationException()
    }

    private class GuardedTls(private val f: javax.net.ssl.SSLSocketFactory) : javax.net.ssl.SSLSocketFactory() {
        private fun w(s: java.net.Socket): java.net.Socket = GuardedSocket(s as javax.net.ssl.SSLSocket)
        override fun getDefaultCipherSuites(): Array<String> = f.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = f.supportedCipherSuites
        override fun createSocket(s: java.net.Socket, h: String, p: Int, auto: Boolean) = w(f.createSocket(s, h, p, auto))
        override fun createSocket(h: String, p: Int) = w(f.createSocket(h, p))
        override fun createSocket(h: String, p: Int, l: java.net.InetAddress, lp: Int) = w(f.createSocket(h, p, l, lp))
        override fun createSocket(h: java.net.InetAddress, p: Int) = w(f.createSocket(h, p))
        override fun createSocket(h: java.net.InetAddress, p: Int, l: java.net.InetAddress, lp: Int) = w(f.createSocket(h, p, l, lp))
    }

    /** The phone's TLS socket with [GuardedInput] on what it decrypts; everything else is passed through. */
    private class GuardedSocket(private val s: javax.net.ssl.SSLSocket) : javax.net.ssl.SSLSocket() {
        private val input by lazy { GuardedInput(s.inputStream) }
        override fun getInputStream(): java.io.InputStream = input
        override fun getOutputStream(): java.io.OutputStream = s.outputStream
        override fun getSupportedCipherSuites(): Array<String> = s.supportedCipherSuites
        override fun getEnabledCipherSuites(): Array<String> = s.enabledCipherSuites
        override fun setEnabledCipherSuites(v: Array<String>) { s.enabledCipherSuites = v }
        override fun getSupportedProtocols(): Array<String> = s.supportedProtocols
        override fun getEnabledProtocols(): Array<String> = s.enabledProtocols
        override fun setEnabledProtocols(v: Array<String>) { s.enabledProtocols = v }
        override fun getSession(): javax.net.ssl.SSLSession = s.session
        override fun getHandshakeSession(): javax.net.ssl.SSLSession? = s.handshakeSession
        override fun addHandshakeCompletedListener(l: javax.net.ssl.HandshakeCompletedListener) = s.addHandshakeCompletedListener(l)
        override fun removeHandshakeCompletedListener(l: javax.net.ssl.HandshakeCompletedListener) = s.removeHandshakeCompletedListener(l)
        override fun startHandshake() = s.startHandshake()
        override fun setUseClientMode(v: Boolean) { s.useClientMode = v }
        override fun getUseClientMode() = s.useClientMode
        override fun setNeedClientAuth(v: Boolean) { s.needClientAuth = v }
        override fun getNeedClientAuth() = s.needClientAuth
        override fun setWantClientAuth(v: Boolean) { s.wantClientAuth = v }
        override fun getWantClientAuth() = s.wantClientAuth
        override fun setEnableSessionCreation(v: Boolean) { s.enableSessionCreation = v }
        override fun getEnableSessionCreation() = s.enableSessionCreation
        override fun getSSLParameters(): javax.net.ssl.SSLParameters = s.sslParameters
        override fun setSSLParameters(p: javax.net.ssl.SSLParameters) { s.sslParameters = p }
        override fun close() = s.close()
        override fun isClosed() = s.isClosed
        override fun isConnected() = s.isConnected
        override fun isBound() = s.isBound
        override fun isInputShutdown() = s.isInputShutdown
        override fun isOutputShutdown() = s.isOutputShutdown
        override fun shutdownInput() = s.shutdownInput()
        override fun shutdownOutput() = s.shutdownOutput()
        override fun getSoTimeout() = s.soTimeout
        override fun setSoTimeout(t: Int) { s.soTimeout = t }
        override fun getTcpNoDelay() = s.tcpNoDelay
        override fun setTcpNoDelay(v: Boolean) { s.tcpNoDelay = v }
        override fun getKeepAlive() = s.keepAlive
        override fun setKeepAlive(v: Boolean) { s.keepAlive = v }
        override fun getInetAddress(): java.net.InetAddress? = s.inetAddress
        override fun getLocalAddress(): java.net.InetAddress? = s.localAddress
        override fun getPort() = s.port
        override fun getLocalPort() = s.localPort
        override fun getRemoteSocketAddress(): java.net.SocketAddress? = s.remoteSocketAddress
        override fun getLocalSocketAddress(): java.net.SocketAddress? = s.localSocketAddress
    }
}

/** Reports of Public messages waiting to go to the internet relays (spec/FORMAT.md, "Internet relays"). */
object NostrReports {
    private fun prefs(c: Context) = c.getSharedPreferences("mesh", 0)
    fun report(c: Context, messageId: String) {
        val s = (pending(c) + messageId).toList().takeLast(200).toSet()
        prefs(c).edit().putStringSet("reports", s).apply()
    }
    fun pending(c: Context): Set<String> = prefs(c).getStringSet("reports", emptySet())!!.toSet()
    fun sent(c: Context, ids: Collection<String>) = prefs(c).edit().putStringSet("reports", pending(c) - ids.toSet()).apply()
}

/**
 * Where the catch-up of each relay and mailbox starts next time (spec/FORMAT.md, "Subscribe"), in seconds, saved on the
 * phone as "<relay url>|<mailbox hex>=<seconds>,…". Same format as the iPhone's RelaySince. Thread-safe.
 */
class RelaySince(saved: String = "") {
    companion object { const val MAX = 400 }
    private val at = LinkedHashMap<String, Long>()
    /** True when something moved since [save]. */
    @Volatile var changed = false; private set
    init {
        for (e in saved.split(',')) { val i = e.lastIndexOf('='); if (i > 0) e.substring(i + 1).toLongOrNull()?.let { at[e.substring(0, i)] = it } }
    }
    @Synchronized fun get(relay: String, mailbox: Int): Long? = at[key(relay, mailbox)]
    /** Moves the start forward to [t]; never back. */
    @Synchronized fun advance(relay: String, mailbox: Int, t: Long) {
        val k = key(relay, mailbox); val old = at[k]
        if (old != null && old >= t) return
        at.remove(k); at[k] = t; changed = true
        while (at.size > MAX) at.remove(at.keys.first())
    }
    @Synchronized fun save(): String { changed = false; return at.entries.joinToString(",") { "${it.key}=${it.value}" } }
    private fun key(relay: String, mailbox: Int) = relay + "|" + "%04x".format(mailbox and 0xFFFF)
}

/** A relay's messages this minute. Outlives its links: dropping the link and coming back doesn't buy a new share. */
class RelayPace { @Volatile var from = 0L; @Volatile var n = 0 }

/**
 * Catch-up on one relay link (spec/FORMAT.md, "Subscribe"): one REQ per mailbox, one mailbox at a time, in the order
 * given (groups before the Public channel), so a busy mailbox never crowds out another. A page that comes back full is
 * followed by an older one (`until`), up to [Nostr.MAX_PAGES] for a group and one for the Public channel. A mailbox
 * whose catch-up ends with EOSE starts next time where this one started; a refused one (CLOSED) or one with no answer
 * is left for the next link. Times in seconds. Not thread-safe: the caller locks. Same as the iPhone's CatchUp.
 */
class CatchUp(private val relay: String, private val since: RelaySince, private val prefix: String = "cu", private val pace: RelayPace = RelayPace()) {
    class Req(val subId: String, val mailbox: Int, val since: Long, val until: Long?) {
        fun text() = Nostr.catchUp(subId, mailbox, since, until)
    }
    private val todo = ArrayDeque<Int>()
    /** Mailboxes caught up on this link: their live events move the saved start forward. */
    val done = HashSet<Int>()
    /** The REQ waiting for its EOSE, and when it was sent. */
    var current: Req? = null; private set
    var sentAt = 0L; private set
    private var startedAt = 0L
    private var pages = 0; private var count = 0; private var oldest = Long.MAX_VALUE; private var n = 0
    private var throttled = false

    /**
     * One more message from this relay: false if it is over its share for this minute. Relays aren't held to the limit
     * for links, which would let one of them use up the share of the others, so each has its own. What this drops is
     * fetched again on the next link: nothing moves the saved start forward once a link went over.
     */
    fun allow(now: Long): Boolean {
        if (now - pace.from >= 60) { pace.from = now; pace.n = 0 }
        if (++pace.n > Nostr.RELAY_PER_MINUTE) { throttled = true; return false }
        return true
    }

    fun add(mailboxes: Collection<Int>) { for (m in mailboxes) if (m !in done && m !in todo && m != current?.mailbox) todo.addLast(m) }

    /** The next REQ to send, if none is waiting for its answer. */
    fun next(now: Long): Req? {
        if (current != null) return null
        val m = todo.removeFirstOrNull() ?: return null
        startedAt = now; pages = 0
        return page(m, maxOf(now - Nostr.KEEP_S, (since.get(relay, m) ?: 0L) - Nostr.SINCE_MARGIN_S), null, now)
    }

    fun event(subId: String, createdAt: Long) { if (current?.subId == subId) { count++; oldest = minOf(oldest, createdAt) } }

    /** [subId] ended: EOSE ([complete]) or CLOSED / no answer. Returns the next REQ: an older page, or the next mailbox. */
    fun end(subId: String, complete: Boolean, now: Long): Req? {
        val c = current?.takeIf { it.subId == subId } ?: return null
        current = null
        if (complete && !throttled) {
            val max = if (c.mailbox == Nostr.PUBLIC_MAILBOX) 1 else Nostr.MAX_PAGES
            if (count >= Nostr.PAGE && pages < max) return page(c.mailbox, c.since, if (oldest == c.until) oldest - 1 else oldest, now)
            done += c.mailbox
            since.advance(relay, c.mailbox, startedAt)
        }
        return next(now)
    }

    /** A live event of [mailbox] made at [createdAt]: once caught up, the saved start follows it (never past now). */
    fun live(mailbox: Int, createdAt: Long, now: Long) { if (mailbox in done && !throttled) since.advance(relay, mailbox, minOf(createdAt, now)) }

    private fun page(m: Int, from: Long, until: Long?, now: Long): Req {
        count = 0; oldest = Long.MAX_VALUE; pages++; sentAt = now
        return Req(prefix + (++n), m, from, until).also { current = it }
    }
}

/**
 * What this phone still has to post to the relays (spec/FORMAT.md, "Publish"), and what they confirmed. Own packets
 * go first, newest first; anyone else's are first looked up with `#x` and posted only if no relay returned the same
 * packet ([Nostr.digest]). A packet counts as sent only once a relay answered ["OK", <event id>, true, …]; if every
 * relay it went to refused it, or none accepted it within 30 s, it is queued again, up to 3 tries. The queues keep
 * the newest packets when full. Thread-safe. Same rules as the iPhone's RelayOutbox.
 */
class RelayOutbox(
    sent: Collection<String> = emptyList(),
    private val now: () -> Long = System::currentTimeMillis,
    private val jitter: () -> Long = { kotlin.random.Random.nextLong(JITTER_MS) },
) {
    companion object {
        const val OWN_MAX = 500; const val CANDIDATES_MAX = 5_000; const val MISSING_MAX = 2_000
        const val SENT_MAX = 3_000; const val ON_RELAYS_MAX = 5_000; const val FLIGHTS_MAX = 300
        const val FRESH_MS = 40 * 60_000L   // own packets younger than this go up without asking first (their date is up to 35 minutes back)
        const val ANSWER_MS = 30_000L       // how long a post waits for a relay to accept it
        const val TRIES = 3
        /** A bridged packet waits up to this long, at random, before the relays are asked about it: phones that got it
         *  at the same moment then don't all find it missing and all post it. Own packets never wait. */
        const val JITTER_MS = 30_000L
    }
    private class Flight(val p: Packet, val fromOwn: Boolean, val relays: Set<String>, val at: Long) {
        val refused = HashSet<String>(); var over = false
    }
    private val own = HashMap<String, Packet>()        // written on this phone: up first, newest first
    private val candidates = HashMap<String, Packet>() // anyone else's, not yet looked up
    private val missing = HashMap<String, Packet>()    // looked up: no relay has them, so this phone posts them
    private val flying = HashSet<String>()             // posted, waiting for an answer
    private val sent = RecentIds(SENT_MAX, sent)        // on the relays already
    private val onRelays = bounded<String>(ON_RELAYS_MAX) // packet id -> digest of the copy a relay sent
    private val flights = object : LinkedHashMap<String, Flight>() { // event id -> post; ended ones stay for late answers
        override fun removeEldestEntry(e: MutableMap.MutableEntry<String, Flight>?): Boolean {
            if (size <= FLIGHTS_MAX) return false
            e?.value?.let { if (!it.over) flying -= it.p.id }
            return true
        }
    }
    private val tries = bounded<Int>(MISSING_MAX)
    private val due = bounded<Long>(CANDIDATES_MAX)    // candidate id -> when the relays may be asked about it
    /** True when the sent list changed since [sentList]: the caller saves it. */
    @Volatile var changed = false; private set

    private fun <V> bounded(max: Int) = object : LinkedHashMap<String, V>() {
        override fun removeEldestEntry(e: MutableMap.MutableEntry<String, V>?) = size > max
    }

    /** The router offers a packet. [mine]: written on this phone (a message or a receipt). */
    @Synchronized fun offer(p: Packet, mine: Boolean) {
        val t = now()
        if (p.id in sent || p.id in flying || onRelays[p.id] == Nostr.digest(p) || p.ts < t - Nostr.KEEP_S * 1000) return
        tries.remove(p.id)
        if (mine && p.ts > t - FRESH_MS) put(own, p, OWN_MAX)
        else if (p.id !in missing && p.id !in own) { put(candidates, p, CANDIDATES_MAX); due.getOrPut(p.id) { t + jitter() } }
    }

    /** The next packet to post: the newest own one, else (if [bridged]) the newest no relay had. Too old ones are skipped. */
    @Synchronized fun next(bridged: Boolean): Pair<Packet, Boolean>? {
        newest(own)?.let { return it to true }
        return if (bridged) newest(missing)?.let { it to false } else null
    }
    private fun newest(q: HashMap<String, Packet>): Packet? {
        val cut = now() - Nostr.KEEP_S * 1000 // checked again right before posting
        q.values.removeAll { it.ts < cut }
        return q.values.maxByOrNull { it.ts }?.also { q.remove(it.id) }
    }

    /** [p] went out as event [eventId] to [relays]. */
    @Synchronized fun posted(eventId: String, p: Packet, fromOwn: Boolean, relays: Set<String>) {
        flights[eventId] = Flight(p, fromOwn, relays, now()); flying += p.id
    }

    /** A relay answered an event. Returns the packet id if this made it sent (the caller reports it), else null. */
    @Synchronized fun answer(relay: String, ok: Nostr.Ok): String? {
        val f = flights[ok.eventId] ?: return null
        if (ok.accepted) { flights.remove(ok.eventId); flying -= f.p.id; return f.p.id.takeIf(::markSent) }
        f.refused += relay
        if (!f.over && f.refused.containsAll(f.relays)) fail(f)
        return null
    }

    /** Posts that no relay accepted within 30 s are queued again. */
    @Synchronized fun expire() { val t = now(); flights.values.filter { !it.over && t - it.at >= ANSWER_MS }.forEach(::fail) }

    private fun fail(f: Flight) {
        f.over = true; flying -= f.p.id
        if (f.p.id in sent) return
        val n = (tries[f.p.id] ?: 0) + 1; tries[f.p.id] = n
        if (n >= TRIES) return // until the router offers it again (next link to the relays)
        if (f.fromOwn) put(own, f.p, OWN_MAX) else put(missing, f.p, MISSING_MAX)
    }

    /** A relay sent this packet. Returns its id if a queued copy is the same packet, which is now sent; else null. */
    @Synchronized fun fromRelay(p: Packet): String? {
        val d = Nostr.digest(p); onRelays[p.id] = d
        val queued = own[p.id] ?: candidates[p.id] ?: missing[p.id] ?: flights.values.firstOrNull { it.p.id == p.id && !it.over }?.p
        return if (queued != null && Nostr.digest(queued) == d && markSent(p.id)) p.id else null
    }

    /** Up to [n] of the newest packets to look up on the relays (`#x`). */
    @Synchronized fun toCheck(n: Int): List<Packet> {
        val t = now()
        return candidates.values.filter { (due[it.id] ?: 0L) <= t }.sortedByDescending { it.ts }.take(n)
            .onEach { candidates.remove(it.id); due.remove(it.id) }
    }

    /** After the lookup: packets a relay returned with the same contents are sent (their ids returned), the rest get posted. */
    @Synchronized fun checked(batch: List<Packet>): List<String> {
        val found = ArrayList<String>()
        for (p in batch) {
            if (onRelays[p.id] == Nostr.digest(p)) { if (markSent(p.id)) found += p.id }
            else if (p.id !in sent && p.id !in flying) put(missing, p, MISSING_MAX)
        }
        return found
    }

    @Synchronized fun sentList(): List<String> { changed = false; return sent.toList() }
    @Synchronized fun isSent(id: String) = id in sent
    @Synchronized fun queued() = own.size + candidates.size + missing.size

    private fun markSent(id: String): Boolean {
        if (!sent.add(id)) return false
        changed = true; own.remove(id); candidates.remove(id); missing.remove(id)
        return true
    }

    /** Full queue: the oldest packet makes room if the new one is newer. */
    private fun put(q: HashMap<String, Packet>, p: Packet, max: Int) {
        if (q.size >= max && p.id !in q) {
            val oldest = q.values.minByOrNull { it.ts } ?: return
            if (oldest.ts >= p.ts) return
            q.remove(oldest.id)
        }
        q[p.id] = p
    }
}

/**
 * Links to public Nostr relays while there is internet (spec/FORMAT.md, "Internet relays"). One peer for forwarding:
 * the router gives it every packet and it hands the router what arrives for this phone's mailboxes. Packets written on
 * this phone go up first. Anyone else's (this phone bridging its neighbourhood) go up only if no relay has them yet,
 * and slowly, so the same packet isn't posted by every phone that holds it and relays don't throttle us ([RelayOutbox]).
 * Each group has its own connections, key and subscription ([RelayScope]), so one connection never shows that two
 * groups share a phone. Packets this phone only passes on go out with the Everyone channel's.
 */
class NostrLink(
    private val ctx: Context,
    private val router: () -> MeshRouter?,
    private val scopes: () -> List<Scope>,
    private val changed: () -> Unit,
    private val viaTor: Boolean = false, // "Connect through Tor": links go only through the app's own Tor
    private val onRelays: (String) -> Unit = {}, // a relay accepted a packet, or had it already
) {
    /** One group's mailboxes; [id] is empty for the Everyone channel. */
    class Scope(val id: String, val mailboxes: List<Int>)

    companion object {
        const val PEER = "nostr"
        fun owns(peer: String) = peer == PEER
        /** Free public relays that stored a 22 KB event of this kind from a new key (tested 2026-11-06). */
        val RELAYS = listOf("wss://nos.lol", "wss://relay.damus.io", "wss://relay.primal.net", "wss://nostr.mom", "wss://nostr.oxtr.dev", "wss://relay.ditto.pub")
        /** Through Tor: nos.lol and nostr.mom don't answer Tor exits (tested 2026-11-06), so two others take their place. */
        val TOR_RELAYS = listOf("wss://relay.damus.io", "wss://relay.primal.net", "wss://nostr.oxtr.dev", "wss://relay.ditto.pub", "wss://relay.nostr.net", "wss://nostr.data.haus")
    }

    private val h = android.os.Handler(android.os.Looper.getMainLooper())
    private val rnd = java.security.SecureRandom()
    private val POST_SPREAD_MS = 8_000 // so the time a packet reaches a relay says less about when it was written
    private val links = LinkedHashMap<String, RelayScope>() // scope id -> its links (lock it)
    @Volatile private var boxes: Map<String, List<Int>> = emptyMap()
    @Volatile private var running = false
    private var linksUp = 0 // scopes with at least one relay linked (lock links)

    private val everyone get() = synchronized(links) { links[""] }
    val connected get() = synchronized(links) { links.values.maxOfOrNull { it.connected } ?: 0 }
    val isUp get() = synchronized(links) { linksUp > 0 }
    val total get() = everyone?.total ?: 0
    val throughTor get() = everyone?.throughTor
    val torStuck get() = everyone?.torStuck == true
    fun statusLine() = everyone?.statusLine() ?: "Internet: off"

    fun start() { running = true; sync() }

    fun stop() {
        running = false
        synchronized(links) { links.values.toList().also { links.clear() } }.forEach { it.stop() }
    }

    /** The groups or their keys changed: new groups get their own links, and every link asks for its current mailboxes. */
    fun resubscribe() { sync(); synchronized(links) { links.values.toList() }.forEach { it.resubscribe() } }

    /** Called by the router: a packet goes up on the links of the group it belongs to, or else with the Everyone channel's. This phone's own wait a moment, at random. */
    fun send(p: Packet, mine: Boolean) { if (mine) h.postDelayed({ route(p, true) }, rnd.nextInt(POST_SPREAD_MS).toLong()) else route(p, false) }

    private fun route(p: Packet, mine: Boolean) {
        val box = Packet.mailbox(p.id)
        val id = boxes.entries.firstOrNull { it.key.isNotEmpty() && box in it.value }?.key ?: ""
        synchronized(links) { links[id] ?: links[""] }?.send(p, mine)
    }

    private fun sync() {
        if (!running) return
        val now = scopes().distinctBy { it.id }
        boxes = now.associate { it.id to it.mailboxes }
        val (gone, fresh) = synchronized(links) {
            links.keys.filter { it !in boxes }.mapNotNull { links.remove(it) } to now.filter { it.id !in links }.map { s ->
                RelayScope(ctx, s.id, router, ::scopeUp, { boxes[s.id] ?: emptyList() }, changed, viaTor, onRelays).also { links[s.id] = it }
            }
        }
        gone.forEach { it.stop() }; fresh.forEach { it.start() }
    }

    /** The router sees one peer, up while any scope has a relay. */
    private fun scopeUp(on: Boolean) {
        val edge = synchronized(links) { linksUp += if (on) 1 else -1; if (on) linksUp == 1 else linksUp == 0 }
        if (edge) router()?.let { if (on) it.peerUp(PEER) else it.peerDown(PEER) }
    }
}

/** One group's links to the relays (or the Everyone channel's, when [scope] is empty): its own sockets, key and subscription. */
private class RelayScope(
    private val ctx: Context,
    private val scope: String,
    private val router: () -> MeshRouter?,
    private val onUp: (Boolean) -> Unit,
    private val mailboxes: () -> List<Int>,
    private val changed: () -> Unit,
    private val viaTor: Boolean,
    private val onRelays: (String) -> Unit,
) {
    companion object {
        private const val START_SPREAD_MS = 8_000   // groups link at different moments, so their connections don't line up
        private const val TICK_MS = 1_500L          // at most one own packet per tick
        private const val BRIDGE_EVERY = 3          // and one bridged packet every 3 ticks
        private const val CHECK_MS = 10_000L        // how often to ask relays which bridged packets they have
        private const val CHECK_WAIT_MS = 6_000L    // how long to wait for their answers
        private const val CHECK_BATCH = 50
        private const val REST_MS = 10 * 60_000L    // pause posting to a relay that says to slow down
        private const val CATCH_UP_WAIT_S = 20L     // a catch-up REQ with no EOSE by then is given up on this link
    }

    private val secret = Schnorr.newSecret() // a new throwaway key every start and for each group: relays can't link them by key
    private val relays = DebugTools.relays(ctx) ?: if (viaTor) NostrLink.TOR_RELAYS else NostrLink.RELAYS // the override exists in debug builds only
    private val saved = if (scope.isEmpty()) "" else ".$scope" // the Everyone links keep the names older builds used
    private val torUser = ByteArray(8).also(java.security.SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) } // its own Tor circuits
    private val h = android.os.Handler(android.os.Looper.getMainLooper())
    // Battery saver: the radio wakes less often for keep-alive pings.
    private val direct = okhttp3.OkHttpClient.Builder().pingInterval(if (MeshEngine.batterySaver(ctx)) 120L else 30L, java.util.concurrent.TimeUnit.SECONDS)
        // No compression: a hostile relay could inflate a small message into hundreds of MB and end the app.
        .addInterceptor { c ->
            // An unchecked exception from what a relay answered would end the app on OkHttp's thread: it ends the link instead.
            try { c.proceed(c.request().newBuilder().removeHeader("Sec-WebSocket-Extensions").build()) }
            catch (e: RuntimeException) { throw java.io.IOException("relay's answer broke the link", e) }
        }
        .apply { WsLimit.apply(this, plain = relays.any { it.startsWith("ws://") }) }.build()
    private var client = direct // through Tor's proxy once Tor is up (viaTor)
    private val open = java.util.concurrent.ConcurrentHashMap<String, okhttp3.WebSocket>()
    private val sockets = java.util.concurrent.ConcurrentHashMap<String, okhttp3.WebSocket>()
    private val backoff = java.util.concurrent.ConcurrentHashMap<String, Long>()
    private val resting = java.util.concurrent.ConcurrentHashMap<String, Long>() // relay -> post again after
    private val catchUps = java.util.concurrent.ConcurrentHashMap<String, CatchUp>() // relay -> its catch-up (lock it)
    private val paces = java.util.concurrent.ConcurrentHashMap<String, RelayPace>()  // relay -> what it sent this minute
    private val prefs = ctx.getSharedPreferences("mesh", 0)
    private val outbox = RelayOutbox(prefs.getString("relaySent$saved", "")!!.split(',').filter { it.isNotEmpty() })
    private val since = RelaySince(prefs.getString("relaySince$saved", "") ?: "")
    private val events = java.util.Collections.synchronizedMap(object : LinkedHashMap<String, Pair<String, String>>() {
        override fun removeEldestEntry(e: MutableMap.MutableEntry<String, Pair<String, String>>?) = size > 2_000
    }) // packet id -> (event id, author), for reports
    @Volatile private var running = false
    @Volatile private var up = false
    @Volatile private var live = "live" + System.nanoTime().toString(36)
    private var ticks = 0
    private var checking = false
    private var torCheck = false // a Tor check is running

    /** With Tor: true once a check says traffic leaves through Tor, false while Tor starts. Null without Tor. */
    @Volatile var throughTor: Boolean? = if (viaTor) false else null; private set
    /** Since when this link has been waiting for Tor (0 while it isn't). */
    @Volatile private var torWaitSince = if (viaTor) System.currentTimeMillis() else 0L
    /** Tor has been trying for over 2 minutes without a working circuit (no internet, or Tor blocked). */
    val torStuck get() = throughTor == false && torWaitSince > 0 && System.currentTimeMillis() - torWaitSince > 120_000L

    val connected get() = open.size
    /** True while at least one relay is linked (it then counts as one peer for the router, not as a phone). */
    val isUp get() = up
    val total get() = relays.size

    /**
     * OkHttp has no limit on one message, so a hostile relay could send one big enough to end the app. When memory runs
     * short, every relay link is dropped, which frees what it was reading; they reconnect as after any failure.
     */
    private val memoryWatch = object : Runnable {
        override fun run() {
            if (!running) return
            val rt = Runtime.getRuntime()
            if (rt.totalMemory() - rt.freeMemory() > rt.maxMemory() / 10 * 8) { DebugTools.log("relays: memory is short, dropping links"); sockets.values.forEach { it.cancel() } }
            h.postDelayed(this, 2_000)
        }
    }

    fun start() {
        if (running) return
        running = true
        h.removeCallbacks(memoryWatch); h.post(memoryWatch)
        val wait = if (scope.isEmpty()) 0L else java.security.SecureRandom().nextInt(START_SPREAD_MS).toLong()
        h.postDelayed({ if (!viaTor) relays.forEach(::connect) else waitForTor() }, wait) // Tor checks run on the main thread
        h.postDelayed(::pump, TICK_MS)
        h.postDelayed(::check, CHECK_MS)
    }

    fun stop() {
        running = false
        h.removeCallbacksAndMessages(null)
        sockets.values.forEach { it.close(1000, null) }; sockets.clear(); open.clear(); catchUps.clear()
        if (up) { up = false; onUp(false) }
        save()
        changed()
    }

    /** The groups changed: every relay gets the new live subscription and catches up the new mailboxes. */
    fun resubscribe() {
        val old = live; live = "live" + System.nanoTime().toString(36)
        val boxes = mailboxes()
        for ((url, ws) in open) {
            ws.send(Nostr.close(old)); ws.send(Nostr.live(live, boxes))
            val cu = catchUps[url] ?: continue
            synchronized(cu) { cu.add(boxes); cu.next(nowS()) }?.let { ws.send(it.text()) }
        }
    }

    /**
     * Called by the router: queues the packet unless it came from the relays, is on them already or is too old.
     * [mine] = written on this phone (a message or a receipt). Older own packets may be on the relays already (the
     * app can be killed before it saves what it posted), so they are looked up first, like anyone else's.
     */
    fun send(p: Packet, mine: Boolean) = outbox.offer(p, mine)

    /**
     * Starts the app's Tor if needed, waits for it, checks through it that traffic leaves through Tor, then links to
     * the relays; else tries again soon.
     */
    private fun waitForTor() {
        if (!running || torCheck) return
        Tor.start(ctx)
        val port = Tor.socksPort() ?: run { h.postDelayed(::waitForTor, 2_000); return } // still starting
        val socks = Socks5.factory(port, torUser)
        client = direct.newBuilder().socketFactory(socks).dns(Socks5.noDns).build()
        torCheck = true
        val c = okhttp3.OkHttpClient.Builder().socketFactory(socks).dns(Socks5.noDns).build() // an ordinary request: the relay links' guard takes only WebSocket answers
        Thread {
            val ok = Tor.check(c, scope.take(6).ifEmpty { "everyone" })
            h.post {
                torCheck = false
                if (!running) return@post
                throughTor = ok; if (ok) torWaitSince = 0L; changed()
                if (ok) relays.filter { !sockets.containsKey(it) }.forEach(::connect) else h.postDelayed(::waitForTor, 15_000)
            }
        }.start()
    }

    private fun connect(url: String) {
        if (!running || (viaTor && throughTor != true)) return // with Tor: only after the check
        val ws = client.newWebSocket(okhttp3.Request.Builder().url(url).build(), object : okhttp3.WebSocketListener() {
            override fun onOpen(ws: okhttp3.WebSocket, r: okhttp3.Response) {
                open[url] = ws; backoff.remove(url)
                DebugTools.log("relay open ${url.substringAfter("//")} ${scope.take(6).ifEmpty { "everyone" }}")
                val boxes = mailboxes()
                ws.send(Nostr.live(live, boxes))
                val cu = CatchUp(url, since, pace = paces.getOrPut(url) { RelayPace() }).also { it.add(boxes) }
                catchUps[url] = cu
                synchronized(cu) { cu.next(nowS()) }?.let { ws.send(it.text()) }
                if (!up) { up = true; onUp(true) } // the router then offers every stored packet
                changed()
            }
            override fun onMessage(ws: okhttp3.WebSocket, text: String) {
                Nostr.ok(text)?.let { ok ->
                    if (!ok.accepted) {
                        android.util.Log.w("DarkProof", "relay $url refused an event: ${ok.reason.take(150)}")
                        if (Nostr.isThrottle(ok.reason)) resting[url] = System.currentTimeMillis() + REST_MS
                    }
                    outbox.answer(url, ok)?.let(onRelays) // "Sent" only once a relay took it
                    return
                }
                Nostr.end(text)?.let { e ->
                    val cu = catchUps[url] ?: return
                    synchronized(cu) { cu.end(e.subId, e.complete, nowS()) }?.let { ws.send(it.text()) } // older page or next mailbox
                    return
                }
                if (catchUps[url]?.let { cu -> synchronized(cu) { cu.allow(nowS()) } } == false) return
                val r = Nostr.received(text) ?: return
                events[r.packet.id] = r.eventId to r.pubkey
                catchUps[url]?.let { cu ->
                    synchronized(cu) { if (r.subId == live) cu.live(Packet.mailbox(r.packet.id), r.createdAt, nowS()) else cu.event(r.subId, r.createdAt) }
                }
                outbox.fromRelay(r.packet)?.let(onRelays)
                router()?.receive(NostrLink.PEER, r.packet) // also answers to the #x lookups: the router ignores packets it already has
            }
            override fun onClosed(ws: okhttp3.WebSocket, code: Int, reason: String) = lost(url, ws)
            override fun onFailure(ws: okhttp3.WebSocket, t: Throwable, r: okhttp3.Response?) = lost(url, ws)
        })
        sockets[url] = ws
    }

    private fun lost(url: String, ws: okhttp3.WebSocket) {
        if (sockets[url] !== ws) return
        sockets.remove(url); open.remove(url); catchUps.remove(url)
        if (open.isEmpty() && up) { up = false; onUp(false) }
        if (open.isEmpty() && throughTor == true) { throughTor = false; torWaitSince = System.currentTimeMillis(); h.post(::waitForTor) } // Tor lost its circuits? check again
        changed()
        if (!running) return
        val wait = ((backoff[url] ?: 2_500L) * 2).coerceAtMost(120_000L) // no internet: try again, less and less often
        backoff[url] = wait
        h.postDelayed({ connect(url) }, wait)
    }

    /**
     * Every tick: one own packet, else (every few ticks) one bridged packet no relay had, else pending reports. Only
     * to relays that aren't resting; with none, packets stay queued.
     */
    private fun pump() {
        if (!running) return
        ticks++
        outbox.expire() // posts no relay accepted in time go back in the queue
        val now = System.currentTimeMillis()
        val ready = open.filterKeys { (resting[it] ?: 0L) < now }
        if (ready.isNotEmpty()) {
            val next = outbox.next(bridged = ticks % BRIDGE_EVERY == 0)
            if (next != null) post(next.first, next.second, ready) else sendReports()
        }
        save()
        h.postDelayed(::pump, TICK_MS)
    }

    private fun post(p: Packet, fromOwn: Boolean, to: Map<String, okhttp3.WebSocket>) {
        val e = Nostr.event(p, secret, Nostr.blurred(nowS()))
        val msg = Nostr.publish(e)
        outbox.posted(e.getString("id"), p, fromOwn, to.filter { (_, ws) -> ws.send(msg) }.keys.toSet())
    }

    /** The sent list and the catch-up starts, when they changed. */
    private fun save() {
        if (outbox.changed) prefs.edit().putString("relaySent$saved", outbox.sentList().joinToString(",")).apply()
        if (since.changed) prefs.edit().putString("relaySince$saved", since.save()).apply()
    }

    /** Asks the relays which of the newest unchecked bridged packets they have; the rest get posted. Also ends stuck catch-ups. */
    private fun check() {
        if (!running) return
        h.postDelayed(::check, CHECK_MS)
        catchUpTimeouts()
        if (checking || open.isEmpty()) return
        val batch = outbox.toCheck(CHECK_BATCH)
        if (batch.isEmpty()) return
        checking = true
        val subId = "have" + System.nanoTime().toString(36)
        val req = Nostr.have(subId, batch.map { it.id })
        open.values.forEach { it.send(req) }
        h.postDelayed({
            open.values.forEach { it.send(Nostr.close(subId)) }
            outbox.checked(batch).forEach(onRelays) // only copies with the same contents count (Nostr.digest)
            checking = false
        }, CHECK_WAIT_MS)
    }

    private fun catchUpTimeouts() {
        val now = nowS()
        for ((url, cu) in catchUps) {
            val ws = open[url] ?: continue
            val next = synchronized(cu) {
                val c = cu.current ?: return@synchronized null
                if (now - cu.sentAt < CATCH_UP_WAIT_S) return@synchronized null
                ws.send(Nostr.close(c.subId)); cu.end(c.subId, false, now)
            }
            next?.let { ws.send(it.text()) }
        }
    }

    private fun nowS() = System.currentTimeMillis() / 1000

    private fun sendReports() {
        val done = ArrayList<String>()
        for (id in NostrReports.pending(ctx)) {
            val (eventId, author) = events[id] ?: continue // only messages that came from relays can be reported there
            val msg = Nostr.publish(Nostr.report(eventId, author, secret))
            open.values.forEach { it.send(msg) }
            done += id
        }
        if (done.isNotEmpty()) NostrReports.sent(ctx, done)
    }

    fun statusLine(): String = when {
        !running -> "Internet: off"
        throughTor == false -> "Internet: waiting for Tor"
        else -> "Internet: $connected of $total relays" + if (throughTor == true) " through Tor" else ""
    }
}
