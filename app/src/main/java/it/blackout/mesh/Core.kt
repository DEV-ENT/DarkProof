package it.blackout.mesh

import java.io.*
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Unit carried over the network, compact enough to fit in a LoRa packet. Relays see only the id, timestamp, and remaining hops.
 * Wire format: spec/FORMAT.md (shared with the iPhone app).
 */
/** How a packet is padded (spec "Padding"): [SIZE] up to the next listed size, [FULL] to the largest, [NONE] only for test vectors. */
enum class Pad { NONE, SIZE, FULL }

class Packet(val id: String, val ts: Long, val ttl: Int, val cipher: ByteArray) {
    fun encode(): ByteArray = ByteArrayOutputStream().also { b ->
        DataOutputStream(b).run {
            writeByte(MAGIC); write(id.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
            writeLong(ts); writeByte(ttl); write(cipher)
        }
    }.toByteArray()
    fun withTtl(t: Int) = Packet(id, ts, t, cipher)
    companion object {
        private const val MAGIC = 0xB3 // 0xB1 = v0.2 (Java modified UTF-8), 0xB2 = v0.3–0.4 (PBKDF2 keys, device ids), 0xB3 = v0.5
        private const val HEADER = 18
        const val MAX_CIPHER = 16_000
        /** The whole-packet sizes everything is padded to. 163 and 233 are the LoRa limits, so short packets still fit. */
        val SIZES = intArrayOf(163, 233, 512, 1024, 2048, 4096, 8192, HEADER + MAX_CIPHER)
        /** Bytes of plaintext padding for a sealed packet that would otherwise be [size] bytes long. */
        fun padding(size: Int, pad: Pad): Int = when (pad) {
            Pad.NONE -> 0
            Pad.FULL -> maxOf(0, HEADER + MAX_CIPHER - size)
            Pad.SIZE -> (SIZES.firstOrNull { it >= size } ?: size) - size
        }
        /** What sealing adds around the body: packet header, IV, signature, tag. */
        const val OVERHEAD = HEADER + 12 + 64 + 16
        fun newId(): String = ByteArray(8).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        /** A new id whose first 2 bytes are the [mailbox] (spec/FORMAT.md, "Mailboxes"), the other 6 random. */
        fun newId(mailbox: Int): String = "%04x".format(mailbox and 0xFFFF) + newId().substring(4)
        /** The mailbox of any packet id. */
        fun mailbox(id: String): Int = id.substring(0, 4).toInt(16)
        fun decode(raw: ByteArray): Packet? {
            if (raw.size <= HEADER || raw.size > HEADER + MAX_CIPHER || raw[0] != MAGIC.toByte()) return null
            return try {
                DataInputStream(ByteArrayInputStream(raw, 1, raw.size - 1)).run {
                    val id = ByteArray(8).also { readFully(it) }.joinToString("") { "%02x".format(it) }
                    val ts = readLong(); val ttl = readUnsignedByte()
                    if (ttl > 64) return null
                    Packet(id, ts, ttl, raw.copyOfRange(HEADER, raw.size))
                }
            } catch (_: Exception) { null }
        }
    }
}

/**
 * [public]: sent on the Public channel (spec/FORMAT.md), readable by everyone. [photo]: a small JPEG, or null.
 * [group]: the code of the saved group whose key opened it (null for Public messages). Not sent on the wire.
 */
data class Message(val id: String, val ts: Long, val sender: String, val name: String, val text: String,
                   val public: Boolean = false, val photo: ByteArray? = null, val group: String? = null,
                   /** false: the sender's public key isn't known yet, so its signature couldn't be checked (spec "Signatures"). */
                   val verified: Boolean = true)

class GroupCrypto private constructor(private val keyBytes: ByteArray, mailbox: Int?) {
    constructor(code: String) : this(deriveKey(code), null)
    /** The group's relay mailbox (spec/FORMAT.md, "Mailboxes"): receipts share it, so members get them too. */
    val mailbox: Int = mailbox ?: deriveMailbox(keyBytes)
    private val key = SecretKeySpec(keyBytes, "AES")
    private val rnd = SecureRandom()

    /** The group's delivery-receipt key (spec/FORMAT.md, "Delivery receipts"). */
    fun receipts() = GroupCrypto(deriveReceiptKey(keyBytes), mailbox)

    /** The group's introduction key (spec/FORMAT.md, "Introductions"). */
    fun intros() = GroupCrypto(deriveIntroKey(keyBytes), mailbox)

    /** The door's rekey key (spec/DESIGN-v0.6-groups.md, "New key"): new epoch secrets travel sealed with it. */
    fun rekeys() = GroupCrypto(hkdf(keyBytes, "darkproof-rekey-v1"), mailbox)

    /**
     * The group's id, from the key its code makes: it stays the same when the group's code or epoch changes
     * (spec/DESIGN-v0.6-groups.md), so member keys, saved public keys and checked people hang off it.
     */
    fun groupId(): String = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(keyBytes, "HmacSHA256")); doFinal("darkproof-group-id-v1".toByteArray()) }
        .copyOf(16).joinToString("") { "%02x".format(it) }

    /** HMAC-SHA256(key, "darkproof-sig-context-v1"): ties signatures to this key (spec "Signatures"). */
    private val context: ByteArray = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(keyBytes, "HmacSHA256")); doFinal("darkproof-sig-context-v1".toByteArray()) }

    /** Names this key without revealing it, e.g. for the Keystore alias of the member key: half the context, in hex. */
    val tag: String = context.copyOf(16).joinToString("") { "%02x".format(it) }

    /** What a packet's signature covers: tag, context, id, ts, body. */
    fun signed(id: String, ts: Long, body: ByteArray): ByteArray = ByteArrayOutputStream().also { b ->
        b.write("darkproof-sig-v1".toByteArray()); b.write(context)
        b.write(id.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
        DataOutputStream(b).writeLong(ts); b.write(body)
    }.toByteArray()

    /**
     * Seals a signed packet: [sign] gets the signed message and returns r ‖ s. [photo] or [extra] is the 4th field.
     * [iv] is random in normal use; tests pass a fixed one to reproduce spec/test-vectors.txt. Zero bytes after the
     * fields pad the packet ([pad]): they are encrypted and signed, and readers ignore them, so relays can't tell a
     * short message from a long one or count a group's members from the size of a new key.
     */
    fun seal(id: String, ts: Long, sender: String, name: String, text: String, photo: ByteArray? = null, extra: ByteArray? = null,
             iv: ByteArray = ByteArray(12).also(rnd::nextBytes), pad: Pad = Pad.SIZE, sign: (ByteArray) -> ByteArray): ByteArray {
        require(photo == null || photo.size <= Photo.MAX_BYTES) { "photo too big" }
        val fields = ByteArrayOutputStream().also { b ->
            b.putStr(sender); b.putStr(name); b.putStr(text)
            if (photo != null) b.putBytes(byteArrayOf(Photo.JPEG) + photo) else if (extra != null) b.putBytes(extra)
        }.toByteArray()
        val body = fields + ByteArray(Packet.padding(Packet.OVERHEAD + fields.size, pad))
        val sig = sign(signed(id, ts, body)); require(sig.size == 64) { "signature must be r ‖ s" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv)); c.updateAAD("$id|$ts".toByteArray())
        return iv + c.doFinal(sig + body)
    }

    /** An opened packet: the message, its signature, SHA-256 of what it signs, and the raw 4th field. Not checked yet. */
    class Opened(val message: Message, val signature: ByteArray, val digest: ByteArray, val extra: ByteArray?) {
        /** The message key that opened it, if one did. */
        var leaf: Leaf? = null
    }

    private fun headerMask(iv: ByteArray) = MessageKeys.hmac(keyBytes, "darkproof-header-v1".toByteArray() + iv)

    /** Which sender's which message a packet says it is (spec "Message keys"): 3 bytes after the IV, readable with this key. */
    fun header(p: Packet): Pair<Int, Int>? {
        if (p.cipher.size < 12 + 3 + 16) return null
        val m = headerMask(p.cipher.copyOf(12))
        return ((p.cipher[12].toInt() xor m[0].toInt()) and 0xFF) to
            ((((p.cipher[13].toInt() xor m[1].toInt()) and 0xFF) shl 8) or ((p.cipher[14].toInt() xor m[2].toInt()) and 0xFF))
    }

    /** Seals a message with its own key [mk]: message [counter] of the sender at [index] in the epoch's member list. */
    fun sealWith(mk: ByteArray, index: Int, counter: Int, id: String, ts: Long, sender: String, name: String, text: String, photo: ByteArray? = null,
                 iv: ByteArray = ByteArray(12).also(rnd::nextBytes), pad: Pad = Pad.SIZE, sign: (ByteArray) -> ByteArray): ByteArray {
        require(photo == null || photo.size <= Photo.MAX_BYTES) { "photo too big" }
        val fields = ByteArrayOutputStream().also { b ->
            b.putStr(sender); b.putStr(name); b.putStr(text)
            if (photo != null) b.putBytes(byteArrayOf(Photo.JPEG) + photo)
        }.toByteArray()
        val body = fields + ByteArray(Packet.padding(Packet.OVERHEAD + 3 + fields.size, pad))
        val sig = sign(signed(id, ts, body)); require(sig.size == 64) { "signature must be r ‖ s" }
        val h = byteArrayOf(index.toByte(), (counter ushr 8).toByte(), counter.toByte()); val m = headerMask(iv)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(mk, "AES"), GCMParameterSpec(128, iv)); c.updateAAD("$id|$ts".toByteArray() + h)
        return iv + byteArrayOf((h[0].toInt() xor m[0].toInt()).toByte(), (h[1].toInt() xor m[1].toInt()).toByte(), (h[2].toInt() xor m[2].toInt()).toByte()) + c.doFinal(sig + body)
    }

    /** Opens a message sealed with [sealWith]. Its time is taken from the blurred header, or [at] when the packet is local. */
    fun openWith(mk: ByteArray, index: Int, counter: Int, p: Packet, at: Long? = null): Opened? = try {
        val ts = at ?: realTime(p.ts, p.cipher)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(mk, "AES"), GCMParameterSpec(128, p.cipher, 0, 12))
        c.updateAAD("${p.id}|$ts".toByteArray() + byteArrayOf(index.toByte(), (counter ushr 8).toByte(), counter.toByte()))
        parsed(p.id, ts, c.doFinal(p.cipher, 15, p.cipher.size - 15))
    } catch (_: Exception) { null }

    private fun parsed(id: String, ts: Long, plain: ByteArray): Opened? = try {
        if (plain.size < 64 + 6) null else {
            val body = plain.copyOfRange(64, plain.size)
            DataInputStream(ByteArrayInputStream(body)).run {
                val sender = getStr(); val name = getStr(); val text = getStr()
                val extra = if (available() >= 2) runCatching { getBytes() }.getOrNull()?.takeIf { it.isNotEmpty() } else null // padding reads as an empty field
                val photo = extra?.takeIf { it.size > 1 && it[0] == Photo.JPEG && it.size - 1 <= Photo.MAX_BYTES }?.copyOfRange(1, extra.size)
                Opened(Message(id, ts, sender, name, text, photo = photo), plain.copyOf(64),
                    java.security.MessageDigest.getInstance("SHA-256").digest(signed(id, ts, body)), extra)
            }
        }
    } catch (_: Exception) { null }

    private fun timeMask(cipher: ByteArray): Long = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(keyBytes, "HmacSHA256")); update("darkproof-time-v1".toByteArray()); doFinal(cipher.copyOf(12))
    }.let { (((it[0].toLong() and 0xFF) shl 16) or ((it[1].toLong() and 0xFF) shl 8) or (it[2].toLong() and 0xFF)) and (TIME_WINDOW - 1) }

    /** The time to put in the clear header of a packet sealed at [ts] (spec "Times"): up to 35 minutes back, and only this key can tell the real one. */
    fun hideTime(ts: Long, cipher: ByteArray): Long = (ts and (TIME_WINDOW - 1).inv()) - TIME_WINDOW + ((ts and (TIME_WINDOW - 1)) xor timeMask(cipher))
    private fun realTime(wire: Long, cipher: ByteArray): Long = (wire and (TIME_WINDOW - 1).inv()) + TIME_WINDOW + ((wire and (TIME_WINDOW - 1)) xor timeMask(cipher))

    /** A packet's [Message.ts] is the real time. A packet whose header wasn't blurred (test vectors) opens too. */
    fun openSigned(p: Packet): Opened? = openAt(p, realTime(p.ts, p.cipher)) ?: openAt(p, p.ts)

    private fun openAt(p: Packet, ts: Long): Opened? = try {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, p.cipher, 0, 12)); c.updateAAD("${p.id}|$ts".toByteArray())
        parsed(p.id, ts, c.doFinal(p.cipher, 12, p.cipher.size - 12))
    } catch (_: Exception) { null }

    /** The message without checking its signature: tests and debug tools only. */
    fun open(p: Packet): Message? = openSigned(p)?.message

    companion object {
        private val keys = HashMap<String, ByteArray>()
        const val TIME_WINDOW = 1L shl 20 // ms, about 17 minutes

        /** A group's keys from a 32-byte epoch secret instead of a code (spec/DESIGN-v0.6-groups.md, "Keys"). */
        fun fromSecret(secret: ByteArray): GroupCrypto { require(secret.size == 32); return GroupCrypto(secret.copyOf(), null) }

        /**
         * scrypt (N 32768, r 8, p 1) over the UTF-8 bytes of the group code, normalized to NFC first so that "à" typed
         * as one character or as "a" + accent gives the same key on every keyboard and platform. Each code is derived
         * once (it takes 32 MiB and tens of milliseconds); then it comes from memory.
         */
        fun deriveKey(code: String): ByteArray {
            val nfc = java.text.Normalizer.normalize(code, java.text.Normalizer.Form.NFC)
            synchronized(keys) { keys[nfc] }?.let { return it.copyOf() }
            val k = Scrypt.derive(nfc.toByteArray(Charsets.UTF_8), "darkproof-group-v2".toByteArray(), 32768, 8, 1, 32)
            synchronized(keys) { keys[nfc] = k }
            return k.copyOf()
        }
        /** First 2 bytes of HMAC-SHA256(group key, "darkproof-relay-mailbox-v1"), as a number 0-65535. */
        fun deriveMailbox(groupKey: ByteArray): Int = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(groupKey, "HmacSHA256")); doFinal("darkproof-relay-mailbox-v1".toByteArray())
        }.let { ((it[0].toInt() and 0xFF) shl 8) or (it[1].toInt() and 0xFF) }
        /** HKDF-SHA256 (RFC 5869) of the group key, no salt, info "darkproof-receipt-v1", 32 bytes. */
        fun deriveReceiptKey(groupKey: ByteArray): ByteArray {
            val prk = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(ByteArray(32), "HmacSHA256")); doFinal(groupKey) }
            return Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(prk, "HmacSHA256")); update("darkproof-receipt-v1".toByteArray()); doFinal(byteArrayOf(1))
            }
        }
        /** HKDF-SHA256 of the group key, no salt, info "darkproof-intro-v1", 32 bytes. */
        fun deriveIntroKey(groupKey: ByteArray): ByteArray = hkdf(groupKey, "darkproof-intro-v1")
        internal fun hkdf(k: ByteArray, info: String): ByteArray {
            val prk = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(ByteArray(32), "HmacSHA256")); doFinal(k) }
            return Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(prk, "HmacSHA256")); update(info.toByteArray()); doFinal(byteArrayOf(1)) }
        }
        /** Text field: 2-byte big-endian length, then standard UTF-8 (not Java's modified UTF-8, so other platforms can read it). */
        private fun ByteArrayOutputStream.putStr(s: String) = putBytes(s.toByteArray(Charsets.UTF_8))
        private fun ByteArrayOutputStream.putBytes(b: ByteArray) {
            require(b.size <= 0xFFFF) { "field too long" }
            write(b.size ushr 8); write(b.size and 0xFF); write(b)
        }
        private fun DataInputStream.getStr(): String = String(getBytes(), Charsets.UTF_8)
        private fun DataInputStream.getBytes(): ByteArray = ByteArray(readUnsignedShort()).also { readFully(it) }

        /** Code of the Public channel: everyone knows it, so anyone can read and post (spec/FORMAT.md). */
        const val PUBLIC_CODE = "blackout-public"
    }
}

/**
 * A group's epoch secrets (spec/DESIGN-v0.6-groups.md, "Keys"): a phone reads with every one it holds and writes with
 * [current], the highest epoch, and among two of the same epoch the one whose secret has the smaller SHA-256 (every
 * phone picks the same without talking). An epoch goes 7 days after a newer one replaced it; the current one stays.
 */
class Keyring {
    /**
     * [members] and [admins]: member ids, from the rekey that brought it. [by]: who made it. After a removal, [removes]
     * is who went, [code] the group's new code, [via] the code the removal came through, and [rank] where its maker
     * stood among the admins of the epoch before (0 = listed first, the group's creator).
     */
    class Epoch(val number: Long, val made: Long, val secret: ByteArray, val members: List<String> = emptyList(), val admins: List<String> = emptyList(),
                val code: String? = null, val via: String? = null, val removes: String? = null, val by: String? = null, val rank: Int = Int.MAX_VALUE,
                @Volatile var messageKeys: MessageKeys? = null) {
        val group = GroupCrypto.fromSecret(secret); val receipts = group.receipts(); val intros = group.intros()
        val hash: String = java.security.MessageDigest.getInstance("SHA-256").digest(secret).joinToString("") { "%02x".format(it) }
        /** The same epoch with no member list. Numbered below the current one, it opens old messages and proves nothing about who is in. */
        fun forReadingOnly() = Epoch(number, made, secret, emptyList(), admins, code, via, removes, by, rank, messageKeys)

        /** A packet of this epoch: with its own message key if it has one, else (receipts' sealing, older packets) with the epoch's key. */
        fun open(p: Packet): GroupCrypto.Opened? {
            val keys = messageKeys
            if (keys != null) group.header(p)?.let { (i, n) -> keys.key(i, n)?.let { mk -> group.openWith(mk, i, n, p)?.let { o -> o.leaf = Leaf(this, i, n); return o } } }
            return group.openSigned(p)
        }

        companion object {
            /** A new epoch from its random [secret], which isn't kept: only what it derives is, each sender's message keys included (spec "Message keys"). */
            fun fresh(number: Long, made: Long, secret: ByteArray, members: List<String>, admins: List<String>, code: String? = null, via: String? = null,
                      removes: String? = null, by: String? = null, rank: Int = Int.MAX_VALUE) =
                Epoch(number, made, MessageKeys.outer(secret), members, admins, code, via, removes, by, rank, MessageKeys.of(secret, members))
        }
    }
    private val list = ArrayList<Epoch>()

    /** False if this secret was there already. */
    @Synchronized fun add(e: Epoch): Boolean {
        if (list.any { it.hash == e.hash }) return false
        list += e
        if (list.size > MAX_EPOCHS) list.remove(list.maxWith(order)) // every packet is tried with each of them: a flood can't make that endless
        return true
    }

    @Synchronized fun current(): Epoch = currentOrNull()!!
    @Synchronized fun currentOrNull(): Epoch? = list.minWithOrNull(order)

    /** The newest removal: its code is the one the group follows. */
    @Synchronized fun lastMove(): Epoch? = list.filter { it.code != null }.minWithOrNull(order)

    /** True if removal [e] is now the one to follow: the newest, or a late one that beat the rival this phone had followed. */
    @Synchronized fun leads(e: Epoch) = won(e) && (lastMove() === e || list.any { it !== e && it.code != null && it.number == e.number })

    /** Who the removals numbered [number] took out, most senior admin first. A removal by someone a more senior one removed doesn't count. */
    private fun goneAt(number: Long): Set<String> {
        val out = HashSet<String>()
        for (e in list.filter { it.code != null && it.number == number }.sortedWith(order)) if (e.by !in out) e.removes?.let { out += it }
        return out
    }

    /** People a removal that lost took out, who are still in the current epoch: an admin's phone finishes the job. */
    @Synchronized fun stillToRemove(): List<String> {
        val cur = currentOrNull() ?: return emptyList()
        val gone = list.filter { it.code != null }.map { it.number }.distinct().flatMap { goneAt(it) }.toSet()
        return cur.members.filter { it in gone }
    }

    /** Admins added by rekeys of the current number that didn't win: the next rekey an admin makes keeps them. */
    @Synchronized fun rivalAdmins(): List<String> {
        val cur = currentOrNull() ?: return emptyList(); val gone = goneAt(cur.number)
        return list.filter { it.number == cur.number && it !== cur && it.by !in gone }.flatMap { it.admins }.distinct() - cur.admins.toSet() - gone
    }

    /** What a phone does with a rekey whose signature checked out. */
    sealed class Taken {
        /** Not allowed, or nothing for this phone. */
        object Ignored : Taken()
        /** This phone was removed: that removal's epoch number and its maker's rank. */
        class Removed(val number: Long, val rank: Int) : Taken()
        /** This phone is still joining and a removal went past without it: its code no longer works. */
        object Closed : Taken()
        /** A new epoch. [moveTo]: the code the group follows now. [back]: a removal that outranks the one that removed this phone. */
        class Added(val epoch: Epoch, val moveTo: String?, val back: Boolean) : Taken()
    }

    /**
     * The whole decision about rekey [r] (spec "New key"), the same on both apps so that phones given the same rekeys
     * in any order agree. [door]: the code it came through; [oldDoor]: the group has moved on from that code. [me]: this
     * phone's member id. [removedAt]: the removal that removed this phone. [open] opens this phone's sealed part.
     */
    @Synchronized fun take(r: Rekey, maker: String, me: String, door: String, oldDoor: Boolean, removedAt: Pair<Long, Int>?,
                           now: Long = System.currentTimeMillis(), open: (ByteArray) -> ByteArray?): Taken {
        val seniority = rank(r, maker); val mine = r.parts.firstOrNull { it.first == me }
        if (mine == null && me in r.members) return Taken.Ignored // this phone's part is in another packet of the same key
        if (removedAt != null && !(r.removal && r.epoch == removedAt.first && seniority < removedAt.second && mine != null)) return Taken.Ignored
        val admins = admit(r, maker, if (oldDoor) door else null, now) ?: return Taken.Ignored
        val cur = currentOrNull()
        if (r.removal && r.answers == me && cur != null && r.epoch >= cur.number && !outranked(r, maker)) return Taken.Removed(r.epoch, seniority) // a later rejoin has a higher epoch
        if (mine == null) return if (r.removal && cur == null) Taken.Closed else Taken.Ignored
        val (secret, code) = open(mine.second)?.let { Rekey.unbox(it, r.removal) } ?: return Taken.Ignored
        val e = Epoch.fresh(r.epoch, r.made, secret, r.members, admins, code, if (r.removal) door else null, if (r.removal) r.answers else null, maker, if (r.removal) seniority else Int.MAX_VALUE)
        val counted = !exempt(r, maker)
        // A removal can become the current epoch again even when it arrives late, and only an admin can make one.
        if (!add(if (cur != null && r.epoch < cur.number && !r.removal) e.forReadingOnly() else e)) return Taken.Ignored
        if (counted) arrived(maker, now)
        val follow = code != null && leads(e)
        if (follow) dropAbove(e.number)
        return Taken.Added(e, if (follow) code else null, removedAt != null)
    }

    /** After a removal: anything numbered above it was made through the old door by someone who hadn't heard. */
    @Synchronized fun dropAbove(number: Long) { list.removeAll { it.number > number } }

    /** True if [id] was removed before [ts]: what a removed member writes afterwards isn't shown. A removal that lost doesn't count. */
    @Synchronized fun removedBefore(id: String, ts: Long) = list.any { it.removes == id && ts > it.made && won(it) }

    /** True if no other epoch with [e]'s number comes before it. */
    @Synchronized fun won(e: Epoch) = list.none { it !== e && it.number == e.number && order.compare(it, e) < 0 }

    /** Where [maker] stood among the admins of the epoch before [r]: the lower, the more senior. */
    @Synchronized fun rank(r: Rekey, maker: String): Int =
        list.filter { it.number == r.epoch - 1 }.map { it.admins.indexOf(maker) }.filter { it >= 0 }.minOrNull() ?: Int.MAX_VALUE

    /** True if a removal this phone holds outranks [r], so [r] can't take effect. */
    @Synchronized fun outranked(r: Rekey, maker: String): Boolean { val mine = rank(r, maker); return list.any { it.code != null && it.number == r.epoch && it.rank < mine } }

    /**
     * The admins rekey [r] gives its epoch on this phone, or null if it must be ignored (spec "New key"). [maker] is
     * its checked signer; [oldDoor]: the code it came through if the group has moved on from it, else null.
     * - A phone still joining takes the first one that includes it: it has nothing better to trust than the code.
     * - Only admins of the epoch before it may let someone in, leave people out, change the admins or remove someone. A removal needs
     *   that epoch here: picking a higher number can't put it ahead of a removal that outranks it.
     * - Through an old door only a rival removal counts, numbered the same as the removal this phone followed out of it,
     *   or a key numbered below that one, which arrived late.
     * - Older than the current epoch: kept only to read with, so it can't change who is in, and only from someone who
     *   has been a member, or anyone with an old code could fill the phone with keys.
     * - At most one per member per hour, except admins'.
     * - Numbers and times that make no sense, and groups over [MAX_MEMBERS], are refused.
     */
    @Synchronized fun admit(r: Rekey, maker: String, oldDoor: String?, now: Long = System.currentTimeMillis()): List<String>? {
        if (r.epoch !in 1..MAX_EPOCH || r.made < 0 || r.made > now + MAX_AHEAD_MS || r.members.size > MAX_MEMBERS) return null
        val cur = currentOrNull() ?: return if (oldDoor == null) r.admins else null
        if (r.epoch > cur.number + MAX_JUMP) return null
        val earlier = list.filter { it.number == r.epoch - 1 }.sortedWith(order)
        if (r.removal && earlier.isEmpty()) return null
        val before = counting(earlier, cur)
        val byAdmin = before.any { maker in it.admins }
        if (r.removal && (!byAdmin || r.answers in r.members)) return null
        if (oldDoor != null) { val left = list.filter { it.code != null && it.via == oldDoor }.minWithOrNull(order) ?: return null; if (if (r.removal) left.number != r.epoch else r.epoch >= left.number) return null }
        if (!byAdmin && (tooSoon(maker, r.made) || manyLately(maker, now))) return null
        val knownMaker = list.any { maker in it.members }
        if (r.epoch < cur.number) return if (knownMaker) (if (byAdmin) r.admins else before[0].admins) else null
        if (!byAdmin && (maker !in before[0].members || r.members.toSet() != before[0].members.toSet())) return null
        return if (byAdmin) r.admins else before[0].admins
    }

    /** Every epoch, the current one first: the order phones try them in. */
    @Synchronized fun all(): List<Epoch> { val c = currentOrNull() ?: return emptyList(); return listOf(c) + list.filter { it !== c } }

    /**
     * Drops the epochs replaced more than 7 days before [now], never the current one; returns what went. Counted from
     * the next epoch, not this one: a message written on its last day can still arrive a week later.
     */
    @Synchronized fun expire(now: Long): List<Epoch> {
        val c = currentOrNull() ?: return emptyList()
        val gone = list.filter { e -> e !== c && list.filter { it.number > e.number }.minOfOrNull { it.made }?.let { maxOf(it, e.made) < now - KEEP_MS } == true }
        list.removeAll(gone.toSet()); return gone
    }


    private val lately = HashMap<String, ArrayDeque<Long>>() // maker -> when this phone took their last new keys

    /** True if [maker] brought [MAX_KEYS_PER_HOUR] new keys in the last hour by this phone's clock: the date in a key is whatever its maker wrote. */
    private fun manyLately(maker: String, now: Long) = (lately[maker]?.count { now - it < HOUR_MS } ?: 0) >= MAX_KEYS_PER_HOUR

    private fun arrived(maker: String, now: Long) {
        if (lately.size > MAX_MEMBERS * 4) lately.clear() // only limits a flood: forgetting is harmless
        val q = lately.getOrPut(maker) { ArrayDeque() }
        q.addLast(now); while (q.size > MAX_KEYS_PER_HOUR) q.removeFirst()
    }

    /**
     * The epochs that say who is in and who decides, from those [earlier] numbered just before a key: not one kept only
     * for reading, which a member can write with any list they like and so would make themselves an admin; else [cur].
     */
    private fun counting(earlier: List<Epoch>, cur: Epoch) = earlier.filter { it.members.isNotEmpty() }.ifEmpty { listOf(cur) }

    /** True if rules about how often a member may make a key don't apply to [r]: admins, and keys that really let someone in. */
    private fun exempt(r: Rekey, maker: String): Boolean {
        val cur = currentOrNull() ?: return true
        val before = counting(list.filter { it.number == r.epoch - 1 }.sortedWith(order), cur)
        return before.any { maker in it.admins }
    }

    /** True if [maker] already made an epoch within an hour of [made]. */
    @Synchronized fun tooSoon(maker: String, made: Long) = list.any { it.by == maker && kotlin.math.abs(it.made - made) < HOUR_MS }

    /** True if member [maker] made [r] after this phone's current epoch but numbered it lower: their phone missed our keys. */
    @Synchronized fun behind(r: Rekey, maker: String): Boolean { val c = currentOrNull() ?: return false; return !r.removal && r.epoch < c.number && r.made > c.made && maker in c.members }

    companion object {
        const val KEEP_MS = 7 * 24 * 3600_000L
        const val HOUR_MS = 3600_000L
        /** A phone waits a random time up to this after the week is up, so the group's phones don't all make a new key at once. */
        const val MAX_DELAY_MS = 6 * HOUR_MS
        const val MAX_MEMBERS = 100
        private const val MAX_EPOCHS = 64
        private const val MAX_KEYS_PER_HOUR = 4        // from one member, except admins and joins, as they arrive here
        private const val MAX_EPOCH = 1L shl 53
        private const val MAX_JUMP = 1000L             // how far ahead of this phone's epoch a rekey may be numbered
        private const val MAX_AHEAD_MS = 10 * 60_000L  // clocks differ; a date further ahead would put off the weekly key

        /** True if an epoch made at [made] is due for its weekly replacement on a phone whose random delay is [delay]. */
        fun weeklyDue(made: Long, now: Long, delay: Long) = now >= made + KEEP_MS + delay
        /** True if the epoch is past every phone's delay: this phone missed the group's new key, or the whole group was quiet. */
        fun overdue(made: Long, now: Long) = now >= made + KEEP_MS + MAX_DELAY_MS
        /**
         * Highest number first. For the same number a removal beats anything else (or the removed person would still be
         * in), then the most senior admin's removal: its maker can't choose that, as they could a hash. Then the smallest hash.
         */
        private val order = compareByDescending<Epoch> { it.number }.thenBy { it.code == null }.thenBy { it.rank }.thenBy { it.hash }
    }
}

/**
 * A rekey's payload, the 4th field after the type byte (spec/DESIGN-v0.6-groups.md, "New key"): a new epoch, its
 * maker's signing key, the admins, whose join request it answers, and the epoch secret sealed for each member.
 * Type 0x05 is a [removal]: [answers] is then the person removed, and each sealed part also holds the group's new code.
 */
class Rekey(val epoch: Long, val made: Long, val maker: ByteArray, val admins: List<String>, val answers: String?,
            val parts: List<Pair<String, ByteArray>>, val removal: Boolean = false,
            /** Everyone in the new epoch. [parts] can hold only some of them: a big group's key is split over several packets. */
            val members: List<String> = parts.map { it.first }) {

    fun encode(): ByteArray = ByteArrayOutputStream().also { b ->
        DataOutputStream(b).run {
            writeByte((if (removal) REMOVAL else TYPE).toInt()); writeLong(epoch); writeLong(made); write(maker)
            writeByte(admins.size); admins.forEach { write(hex(it)) }
            write(answers?.let(::hex) ?: ByteArray(8))
            writeShort(members.size); members.forEach { write(hex(it)) }
            writeShort(parts.size); parts.forEach { (id, box) -> write(hex(id)); writeShort(box.size); write(box) }
        }
    }.toByteArray()

    companion object {
        const val TYPE: Byte = 6; const val REMOVAL: Byte = 7 // 4 and 5 were the shape without a separate member list
        const val PARTS_PER_PACKET = 10
        /** How many packets a new key for [n] members travels in. Only three counts exist, so the number says little about the group's size. */
        fun packets(n: Int) = when { n <= PARTS_PER_PACKET -> 1; n <= 3 * PARTS_PER_PACKET -> 3; else -> 10 }
        /** [items] spread evenly over that many packets. */
        fun <T> split(items: List<T>): List<List<T>> { val k = packets(items.size); return (0 until k).map { i -> items.filterIndexed { j, _ -> j % k == i } } }
        private const val MAX_CODE = 200 // bytes
        fun hex(id: String): ByteArray = id.chunked(2).map { it.toInt(16).toByte() }.toByteArray().also { require(it.size == 8 || it.size == 16) }
        private fun str(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

        fun decode(e: ByteArray): Rekey? = runCatching {
            DataInputStream(ByteArrayInputStream(e)).run {
                val type = readByte()
                if (type != TYPE && type != REMOVAL) return null
                val epoch = readLong(); val made = readLong(); val maker = ByteArray(33).also(::readFully)
                val admins = (0 until readUnsignedByte()).map { str(ByteArray(8).also(::readFully)) }
                val answers = str(ByteArray(8).also(::readFully)).takeIf { it != "0000000000000000" }
                val members = (0 until readUnsignedShort()).map { str(ByteArray(8).also(::readFully)) }
                val parts = (0 until readUnsignedShort()).map { str(ByteArray(8).also(::readFully)) to ByteArray(readUnsignedShort()).also(::readFully) }
                if (available() != 0 || (type == REMOVAL && answers == null) || parts.any { it.first !in members }) return null
                Rekey(epoch, made, maker, admins, answers, parts, type == REMOVAL, members)
            }
        }.getOrNull()

        /** What is sealed for each member: the epoch secret, then after a removal the group's new code. */
        fun box(secret: ByteArray, code: String?) = secret + (code?.toByteArray(Charsets.UTF_8) ?: ByteArray(0))
        /** The secret and new code from an opened part, or null if it isn't the right shape: anyone with the code can write one. */
        fun unbox(plain: ByteArray, removal: Boolean): Pair<ByteArray, String?>? {
            if (plain.size < 32 || plain.size > 32 + MAX_CODE || (plain.size > 32) != removal) return null
            if (!removal) return plain.copyOf(32) to null
            // Strict, like the iPhone: a code one app accepted and the other refused would split the group.
            val code = runCatching { Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(plain, 32, plain.size - 32)).toString() }.getOrNull() ?: return null
            if (!Invite.isGeneratedCode(code)) return null // a removal can't move the group to a code that can be guessed
            return plain.copyOf(32) to code
        }

        /** HPKE info for a group's rekeys: binds the sealed secret to the door it travels through. */
        fun info(groupId: String) = "darkproof-rekey-v1".toByteArray() + hex(groupId)
        /** HPKE aad for one member's part: binds it to this packet and this member. */
        fun aad(packetId: String, member: String) = hex(packetId) + hex(member)
    }
}

/** Flooding with deduplication and store-and-forward. No Android dependencies. */
class MeshRouter(
    private val send: (peer: String, p: Packet) -> Unit,
    private val deliver: (Packet) -> Unit,
    private val now: () -> Long = System::currentTimeMillis,
    private val retentionMs: Long = 7 * 24 * 3600_000L,
    private val maxStored: Int = 500,
    private val minCipher: Int = 0,
    private val maxPerMinute: Int = 0,
    private val unlimited: (String) -> Boolean = { false },
) {
    companion object {
        /** The smallest real packet: IV, tag, signature and three empty text fields. Anything shorter is junk. */
        const val MIN_SEALED = 12 + 16 + 64 + 6
        /** New packets taken from one link in a minute: far more than phones really send, so a flood costs its sender time. */
        const val LINK_PER_MINUTE = 3_000
        /** Hops a new packet gets. A received packet with more (v0.4 decoding allows up to 64) is lowered to this. */
        const val MAX_TTL = 16
        /** Packets dated more than this ahead of this phone's clock are dropped (spec/FORMAT.md, "Forwarding rules"). */
        const val MAX_FUTURE_MS = 10 * 60_000L
        private const val MAX_SEEN = 50_000 // packets remembered, so a stream of new ones can't fill the memory
        fun inFuture(ts: Long, now: Long) = ts > now + MAX_FUTURE_MS
        fun clamp(p: Packet) = if (p.ttl > MAX_TTL) p.withTtl(MAX_TTL) else p
        /**
         * What makes two packets the same: the id and the content. An id alone isn't enough: someone who sees an id could
         * send junk under it first, and the real packet would then be dropped as a duplicate.
         */
        fun key(p: Packet): String = p.id + ":" + java.security.MessageDigest.getInstance("SHA-256").digest(p.cipher).take(8).joinToString("") { "%02x".format(it) }
    }
    private val peers = LinkedHashSet<String>()
    private var seen = HashSet<String>(); private var seenBefore = HashSet<String>() // two generations: old ones are forgotten
    private var rotatedAt = now()
    private val stored = LinkedHashMap<String, Packet>() // by key, oldest first
    private val cameFrom = HashMap<String, String>()     // key -> the link that brought it (not for this phone's own)
    private val held = HashMap<String, Int>()            // link -> packets of it stored here
    private val pace = HashMap<String, LongArray>()      // link -> [start of this minute, new packets in it]
    @Synchronized fun peerCount() = peers.size
    /**
     * After a restart: [all] is passed on again; [seenKeys] are packets already handled ([key]), so they aren't shown
     * twice. Packets dated in the future are left out. Peers already linked get the packets that are new to the router.
     */
    @Synchronized fun restore(all: List<Packet>, seenKeys: Collection<String> = emptyList()) {
        seen += seenKeys
        val t = now()
        val fresh = all.filter { !inFuture(it.ts, t) && key(it) !in stored }.sortedBy { it.ts }.map(::clamp)
        fresh.forEach { seen += key(it); keep(it, "") }
        for (p in fresh) if (stored.containsKey(key(p))) peers.forEach { forward(it, p) }
    }
    @Synchronized fun publish(p: Packet) { seen += key(p); keep(p, ""); peers.forEach { forward(it, p) } }
    @Synchronized fun peerDown(peer: String) { peers -= peer; pace -= peer }
    @Synchronized fun peerUp(peer: String) { peers += peer; prune(); stored.values.forEach { forward(peer, it) } }
    /** Packets older than 7 days or more than 10 minutes in the future are dropped; ttl above 16 is lowered to 16. */
    @Synchronized fun receive(from: String, packet: Packet) {
        val t = now()
        if (packet.ts < t - retentionMs || inFuture(packet.ts, t) || packet.cipher.size < minCipher) return
        val k = key(packet)
        if (k in seen || k in seenBefore) return
        if (maxPerMinute > 0 && !unlimited(from)) { // not marked as seen: it can still come later, or from someone else
            val w = pace.getOrPut(from) { longArrayOf(t, 0) }
            if (t - w[0] >= 60_000) { w[0] = t; w[1] = 0 }
            if (++w[1] > maxPerMinute) return
        }
        if (t - rotatedAt > retentionMs || seen.size > MAX_SEEN) { seenBefore = seen; seen = HashSet(); rotatedAt = t }
        seen += k
        val p = clamp(packet)
        keep(p, from); deliver(p)
        peers.filter { it != from }.forEach { forward(it, p) }
    }
    private fun forward(peer: String, p: Packet) { if (p.ttl > 1) send(peer, p.withTtl(p.ttl - 1)) }
    private fun keep(p: Packet, from: String) {
        val k = key(p)
        if (stored.put(k, p) == null && from.isNotEmpty()) { cameFrom[k] = from; held[from] = (held[from] ?: 0) + 1 }
        prune()
    }
    private fun drop(k: String) {
        stored.remove(k)
        cameFrom.remove(k)?.let { f -> val n = (held[f] ?: 1) - 1; if (n > 0) held[f] = n else held.remove(f) }
    }
    private fun prune() {
        val cut = now() - retentionMs
        stored.filterValues { it.ts < cut }.keys.toList().forEach(::drop)
        while (stored.size > maxStored) {
            // One link can't push everyone else's packets out: while it holds more than a quarter, its own oldest go first.
            val top = held.maxByOrNull { it.value }
            drop(if (top != null && top.value > maxStored / 4) stored.keys.first { cameFrom[it] == top.key } else stored.keys.first())
        }
    }
}

/**
 * Which stored packets to remove when the store is over its cap (spec/FORMAT.md, "Storage"): first packets no saved
 * group can read, oldest first, then the oldest Public messages, and only then the oldest messages and receipts of
 * the saved groups. Same rules as the iPhone's StoreCap.
 */
/**
 * When a member's encryption key changes (spec "Sealing for one member"). Each key is used for a week, then kept for two
 * more so new keys sealed to it can still be opened, then deleted: after that, recorded traffic sealed to it can't be
 * opened, even by someone who takes the phone. Pure rules; the keys are in [EncKeys]. Same as the iPhone's.
 */
object EncSchedule {
    const val ROTATE_MS = 7 * 24 * 3_600_000L
    const val KEEP_MS = 14 * 24 * 3_600_000L
    const val MAX_KEYS = 8

    /** [replaced]: when a newer key took over; 0 for the current key. Oldest first in a list. */
    data class Entry(val n: Int, val made: Long, val replaced: Long = 0)

    fun parse(s: String): List<Entry> = s.split(',').mapNotNull { e ->
        e.split(':').takeIf { it.size == 3 }?.let { runCatching { Entry(it[0].toInt(), it[1].toLong(), it[2].toLong()) }.getOrNull() }
    }
    fun save(list: List<Entry>) = list.joinToString(",") { "${it.n}:${it.made}:${it.replaced}" }

    fun due(list: List<Entry>, now: Long) = list.lastOrNull()?.let { now - it.made >= ROTATE_MS } ?: true

    /** The list once a new key has taken over. */
    fun rotated(list: List<Entry>, now: Long) =
        list.map { if (it.replaced == 0L) it.copy(replaced = now) else it } + Entry((list.maxOfOrNull { it.n } ?: -1) + 1, now)

    /** The keys that can be deleted now. The current key never is. */
    fun expired(list: List<Entry>, now: Long): List<Entry> {
        val old = list.filter { it.replaced != 0L && now - it.replaced >= KEEP_MS }
        return old + (list - old.toSet()).dropLast(MAX_KEYS)
    }

    /** An introduction replaces a member's encryption key only if it is newer: one played back can't bring back a key they deleted. */
    fun isNewer(known: Long, ts: Long) = ts > known
}

object StoreCap {
    const val MAX_BYTES = 40L * 1024 * 1024
    const val MAX_COUNT = 20_000
    /** In the order they go: [UNREADABLE] first, [GROUP] last. */
    enum class Kind { UNREADABLE, PUBLIC, GROUP }
    /** [size]: the encoded packet's length. */
    class Entry(val id: String, val ts: Long, val size: Int, val kind: Kind)

    /** Ids to remove so that at most [maxBytes] and [maxCount] remain; empty if the store fits. */
    fun overflow(entries: Collection<Entry>, maxBytes: Long = MAX_BYTES, maxCount: Int = MAX_COUNT): List<String> {
        var bytes = entries.sumOf { it.size.toLong() }; var count = entries.size
        if (bytes <= maxBytes && count <= maxCount) return emptyList()
        val out = ArrayList<String>()
        for (e in entries.sortedWith(compareBy<Entry>({ it.kind.ordinal }, { it.ts }, { it.id }))) {
            if (bytes <= maxBytes && count <= maxCount) break
            out += e.id; bytes -= e.size; count--
        }
        return out
    }
}

/**
 * Two links between the same two phones (spec/FORMAT.md, "Wi-Fi networks"): which one stays. When both phones dialed
 * each other at about the same time (the older link is less than 10 s old), the link dialed by the smaller node id
 * stays, so both phones keep the same one. Otherwise, or when the same phone dialed both, the new link replaces the
 * old one: after a restart the old one may be dead without either side knowing.
 */
object DuplicateLinks {
    const val SAME_TIME_MS = 10_000L
    fun keepNew(myId: String, remoteId: String, newDialedByMe: Boolean, oldDialedByMe: Boolean, oldAgeMs: Long): Boolean {
        if (newDialedByMe == oldDialedByMe || oldAgeMs >= SAME_TIME_MS) return true
        val meSmaller = BleProtocol.keepMyCentralLink(myId, remoteId) // byte comparison of the node ids
        return if (newDialedByMe) meSmaller else !meSmaller
    }
}

/** An ordered set of ids that forgets the oldest beyond [max], for lists saved on the phone. Not thread-safe. */
class RecentIds(private val max: Int, initial: Collection<String> = emptyList()) {
    private val set = LinkedHashSet<String>()
    init { initial.forEach(::add) }
    /** True if [id] is new. */
    fun add(id: String): Boolean {
        if (!set.add(id)) return false
        while (set.size > max) set.remove(set.first())
        return true
    }
    operator fun contains(id: String) = id in set
    val size get() = set.size
    fun toList(): List<String> = set.toList()
}

/**
 * When the next delivery receipt goes out (spec/FORMAT.md, "Delivery receipts"): 2 s after the last message to
 * confirm arrived, or 10 s after the first one, so a burst of arriving messages shares one receipt.
 */
object ReceiptBatch {
    const val QUIET_MS = 2_000L
    const val MAX_WAIT_MS = 10_000L
    fun due(firstMs: Long, lastMs: Long, nowMs: Long) = nowMs - lastMs >= QUIET_MS || nowMs - firstMs >= MAX_WAIT_MS
}
