package it.blackout.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Per-message keys (spec "Message keys"). The vector was made by the iPhone's code, so these also check that both apps agree. */
class MessageKeysTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val v = File("../spec/test-vectors.txt").readText().split(Regex("\n\\s*\n"))
        .map { b -> b.lines().filter { it.isNotBlank() && !it.startsWith("#") }.associate { it.substringBefore(": ") to it.substringAfter(": ") } }
        .first { it["kind"] == "message-key" }
    private val anna = "1111111111111111"; private val ben = "2222222222222222"
    private val secret = ByteArray(32) { 9 }
    private val id = "6a44000000000009"; private val ts = 1_794_000_123_456L
    private fun keys() = MessageKeys.of(secret, listOf(anna, ben))

    @Test fun matchesTheSharedVector() {
        val s = unhex(v["secret"]!!); val members = listOf(v["member_0"]!!, v["member_1"]!!)
        val outer = MessageKeys.outer(s); assertEquals(v["outer"], hex(outer))
        val g = GroupCrypto.fromSecret(outer); assertEquals(v["mailbox"]!!.toInt(), g.mailbox)
        val mk = MessageKeys.of(s, members).key(1, 5)!!; assertEquals(v["key_1_5"], hex(mk))
        val t = v["ts"]!!.toLong()
        val c = g.sealWith(mk, 1, 5, v["id"]!!, t, v["sender"]!!, v["name"]!!, v["text"]!!, iv = unhex(v["iv"]!!)) { unhex(v["signature"]!!) }
        assertEquals(v["cipher"], hex(c)); assertEquals(v["wire_ts"]!!.toLong(), g.hideTime(t, c))
        val p = Packet(v["id"]!!, v["wire_ts"]!!.toLong(), 16, unhex(v["cipher"]!!))
        assertEquals(1 to 5, g.header(p))
        val o = g.openWith(mk, 1, 5, p)!!
        assertEquals(v["text"], o.message.text); assertEquals(t, o.message.ts); assertEquals(v["sender"], o.message.sender)
    }

    @Test fun aDeletedKeyIsGoneAndTheOthersStay() {
        val k = keys(); val before = (0..9).map { k.key(1, it)!! }
        k.forget(1, 4)
        assertNull(k.key(1, 4))
        for (i in (0..9) - 4) assertArrayEquals("key $i", before[i], k.key(1, i))
    }

    @Test fun keysCanBeDeletedInAnyOrder() {
        val k = keys(); val whole = keys(); val order = (0 until 300).shuffled(java.util.Random(5))
        order.take(150).forEach { k.forget(0, it) }
        order.take(150).forEach { assertNull(k.key(0, it)) }
        order.drop(150).forEach { assertArrayEquals(whole.key(0, it), k.key(0, it)) }
    }

    @Test fun eachSenderHasItsOwnKeys() { assertTrue(!keys().key(0, 0)!!.contentEquals(keys().key(1, 0)!!)) }

    @Test fun deletingOneSendersKeyLeavesTheOthers() { val k = keys(); k.forget(0, 3); assertNotNull(k.key(1, 3)) }

    @Test fun whatWasDeletedStaysDeletedAfterARestart() {
        val k = keys(); k.forget(1, 7); k.takeNext(); k.takeNext()
        val back = MessageKeys.decode(k.encode())!!
        assertNull(back.key(1, 7)); assertArrayEquals(keys().key(1, 8), back.key(1, 8)); assertEquals(2, back.takeNext()); assertEquals(listOf(anna, ben), back.members)
    }

    @Test fun numbersOutsideTheTreeHaveNoKey() { assertNull(keys().key(0, 65_536)); assertNull(keys().key(0, -1)); assertNull(keys().key(5, 0)) }

    @Test fun whenTheNumbersRunOutThereIsNoNext() {
        val k = MessageKeys.decode(keys().encode().also { java.nio.ByteBuffer.wrap(it).putInt(SenderTree.LEAVES) })!!
        assertNull(k.takeNext())
    }

    private fun epoch() = Keyring.Epoch.fresh(6, 1, secret, listOf(anna, ben), listOf(anna))
    private fun sealedBy(e: Keyring.Epoch, n: Int, sign: (ByteArray) -> ByteArray = { TestKeys.sign(it) }): Packet {
        val c = e.group.sealWith(e.messageKeys!!.key(1, n)!!, 1, n, id, ts, ben, "Ben", "message $n", sign = sign)
        return Packet(id, e.group.hideTime(ts, c), 16, c)
    }

    @Test fun twoPhonesWithTheSameSecretReadEachOther() {
        val o = epoch().open(sealedBy(epoch(), 2))!!
        assertEquals("message 2", o.message.text); assertEquals(ts, o.message.ts); assertEquals(2, o.leaf!!.counter); assertEquals(1, o.leaf!!.index)
    }

    @Test fun oncDeletedTheEpochCantOpenThePacketAgain() {
        val e = epoch(); val p = sealedBy(epoch(), 2)
        e.open(p)!!.leaf!!.forget()
        assertNull(e.open(p))
    }

    @Test fun openingAloneDoesntDeleteTheKey() {
        // A member could forge a packet under someone else's number; the key goes only after the signature has checked.
        val e = epoch(); val forged = sealedBy(epoch(), 3) { ByteArray(64) }
        assertNotNull(e.open(forged)); assertNotNull(e.messageKeys!!.key(1, 3))
    }

    @Test fun theEpochSecretIsntKept() { val e = epoch(); assertTrue(!e.secret.contentEquals(secret)); assertArrayEquals(MessageKeys.outer(secret), e.secret) }

    @Test fun aKeyKeptForReadingStillOpens() { val e = epoch().forReadingOnly(); assertNotNull(e.open(sealedBy(epoch(), 1))) }

    @Test fun theCopyKeepsTheMessage() {
        val key = ByteArray(32) { 3 }; val e = epoch(); val o = e.open(sealedBy(epoch(), 4))!!
        val s = History.open(key, id, History.seal(key, id, "00112233445566778899aabbccddeeff", e.hash, o, 1, 4))!!
        assertEquals("message 4", s.opened.message.text); assertEquals(ts, s.opened.message.ts); assertEquals(e.hash, s.epoch)
        assertArrayEquals(o.digest, s.opened.digest); assertArrayEquals(o.signature, s.opened.signature); assertEquals(1, s.index); assertEquals(4, s.counter)
    }

    @Test fun theCopyNeedsItsKeyAndId() {
        val key = ByteArray(32) { 3 }; val e = epoch(); val o = e.open(sealedBy(epoch(), 4))!!
        val b = History.seal(key, id, "00112233445566778899aabbccddeeff", e.hash, o, 1, 4)
        assertNull(History.open(ByteArray(32), id, b)); assertNull(History.open(key, "6a4400000000000a", b))
    }

    @Test fun aMessageFitsTheSmallestSize() { assertEquals(163, sealedBy(epoch(), 0).encode().size) }
}
