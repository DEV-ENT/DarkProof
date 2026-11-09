package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test

/**
 * Simulated phones running the real decision code ([Keyring.take]), given the same new keys in every order
 * (spec/DESIGN-v0.6-groups.md, step 6). The iPhone's FaultTests check the same cases.
 */
class FaultTest {
    private val anna = "1111111111111111"; private val ben = "2222222222222222"; private val cara = "3333333333333333"
    private val dan = "4444444444444444"; private val eve = "5555555555555555"
    private val all = listOf(anna, ben, cara, dan)
    private val now = 1_000_000_000_000L; private val hour = 3600_000L

    private fun secret(b: Int) = ByteArray(32) { b.toByte() }

    private class Pkt(val r: Rekey, val maker: String, val door: String)

    /** Number [n], by [by], sealed for [members], through code [door]. [removes]: a removal to the new code [code]. */
    private fun pkt(n: Long, by: String, members: List<String>, door: String, s: Int, removes: String? = null, code: String? = null,
                    admins: List<String> = listOf(anna, ben), answers: String? = removes, made: Long = now - 100 * hour + n * hour) =
        Pkt(Rekey(n, made, ByteArray(33), admins.filter { it in members }, answers, members.map { it to Rekey.box(secret(s), code) }, removes != null), by, door)

    /** A phone as the engines run one: it reads the store again after every new epoch, oldest first. */
    private inner class Phone(val me: String, admins: List<String> = listOf(anna, ben)) {
        val ring = Keyring().also { it.add(Keyring.Epoch(5, now - 200 * hour, secret(99), all, admins)) }
        var door = "d1"; val old = ArrayList<String>(); var removedAt: Pair<Long, Int>? = null
        private val seen = ArrayList<Pkt>()
        fun get(p: Pkt) { seen += p; if (tryIt(p)) settle() }
        private fun tryIt(p: Pkt): Boolean {
            if (p.door != door && p.door !in old) return false
            return when (val t = ring.take(p.r, p.maker, me, p.door, p.door != door, removedAt, now) { it }) {
                is Keyring.Taken.Added -> { if (t.back) removedAt = null; t.moveTo?.let { if (it != door) { old.add(0, door); door = it } }; true }
                is Keyring.Taken.Removed -> { removedAt = t.number to t.rank; false }
                else -> false
            }
        }
        private fun settle() { do { var again = false; for (p in seen.sortedBy { it.r.made }) if (tryIt(p)) again = true } while (again) }
    }

    private fun <T> orders(l: List<T>): List<List<T>> = if (l.size < 2) listOf(l) else l.indices.flatMap { i -> orders(l - l[i]).map { listOf(l[i]) + it } }
    private fun phoneAfter(me: String, ps: List<Pkt>) = Phone(me).also { p -> ps.forEach(p::get) }

    @Test fun twoAdminsRemovingDifferentPeopleAtOnce() {
        val a = pkt(6, anna, listOf(anna, ben, cara), "d1", 1, dan, "AAAA-AAAA-AAAA-AAAA"); val b = pkt(6, ben, listOf(anna, ben, dan), "d1", 2, cara, "BBBB-BBBB-BBBB-BBBB")
        for (o in orders(listOf(a, b))) {
            for (me in listOf(anna, ben)) phoneAfter(me, o).let { p ->
                assertEquals("AAAA-AAAA-AAAA-AAAA", p.door); assertEquals(dan, p.ring.current().removes); assertEquals(listOf(cara), p.ring.stillToRemove()); assertNull(p.removedAt)
            }
            phoneAfter(cara, o).let { assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertNull(it.removedAt) } // told first by the removal that lost: undone
            assertNotNull(phoneAfter(dan, o).removedAt)
            // An admin's phone finishes it: Cara goes too, and the group moves again.
            val finish = pkt(7, anna, listOf(anna, ben), "AAAA-AAAA-AAAA-AAAA", 3, cara, "AAAA-AAAA-AAAA-AAA2")
            for (me in listOf(anna, ben)) phoneAfter(me, o + finish).let { assertEquals("AAAA-AAAA-AAAA-AAA2", it.door); assertTrue(it.ring.stillToRemove().isEmpty()) }
            assertNotNull(phoneAfter(cara, o + finish).removedAt)
        }
    }

    @Test fun adminsRemovingEachOther() {
        val a = pkt(6, anna, listOf(anna, cara, dan), "d1", 1, ben, "AAAA-AAAA-AAAA-AAAA"); val b = pkt(6, ben, listOf(ben, cara, dan), "d1", 2, anna, "BBBB-BBBB-BBBB-BBBB")
        for (o in orders(listOf(a, b))) {
            for (me in listOf(anna, cara, dan)) phoneAfter(me, o).let { p ->
                assertEquals("AAAA-AAAA-AAAA-AAAA", p.door); assertNull(p.removedAt); assertTrue(p.ring.stillToRemove().isEmpty()); assertFalse(p.ring.removedBefore(anna, now))
            }
            assertNotNull(phoneAfter(ben, o).removedAt)
        }
    }

    @Test fun aRemovedAdminCantComeBackLater() {
        val out = pkt(6, anna, listOf(anna, cara, dan), "d1", 1, ben, "AAAA-AAAA-AAAA-AAAA")
        val join = pkt(7, anna, listOf(anna, cara, dan, eve), "AAAA-AAAA-AAAA-AAAA", 2, admins = listOf(anna), answers = eve)
        val rival = pkt(6, ben, listOf(ben, cara, dan), "d1", 3, anna, "BBBB-BBBB-BBBB-BBBB")
        phoneAfter(cara, listOf(out, join, rival)).let { assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertEquals(7L, it.ring.current().number); assertFalse(it.ring.removedBefore(anna, now)) }
        // Nor by picking a higher number, nor with an ordinary new key through the old door.
        phoneAfter(cara, listOf(out, join, pkt(8, ben, listOf(ben, cara, dan), "d1", 4, anna, "BBBB-BBBB-BBBB-BBBB"))).let { assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertEquals(7L, it.ring.current().number) }
        phoneAfter(cara, listOf(out, pkt(7, ben, all, "d1", 5))).let { assertEquals(6L, it.ring.current().number) }
    }

    @Test fun theCreatorOverrulesANewerAdmin() {
        val out = pkt(6, ben, listOf(ben, cara, dan), "d1", 1, anna, "BBBB-BBBB-BBBB-BBBB")
        val join = pkt(7, cara, listOf(ben, cara, dan, eve), "BBBB-BBBB-BBBB-BBBB", 2, admins = listOf(ben), answers = eve)
        val rival = pkt(6, anna, listOf(anna, cara, dan), "d1", 3, ben, "AAAA-AAAA-AAAA-AAAA")
        for (o in orders(listOf(out, join, rival))) phoneAfter(cara, o).let { assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertEquals(6L, it.ring.current().number); assertEquals(ben, it.ring.current().removes) }
    }

    @Test fun aRemovalBuiltOnOneThatLost() { // Ben removes Dan, then Anna through his new code, while Anna's rival removal was on its way
        val junior = pkt(6, ben, listOf(anna, ben, cara), "d1", 1, dan, "BBBB-BBBB-BBBB-BBBB")
        val next = pkt(7, ben, listOf(ben, cara), "BBBB-BBBB-BBBB-BBBB", 2, anna, "BBBB-BBBB-BBBB-BBB2")
        val senior = pkt(6, anna, listOf(anna, ben, cara), "d1", 3, dan, "AAAA-AAAA-AAAA-AAAA")
        for (o in orders(listOf(junior, next, senior))) phoneAfter(cara, o).let { assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertEquals(6L, it.ring.current().number) }
    }

    @Test fun newKeysInEveryOrder() {
        val ps = listOf(pkt(6, anna, all, "d1", 1), pkt(7, ben, all, "d1", 2), pkt(8, anna, all + eve, "d1", 3, answers = eve),
            pkt(9, anna, listOf(anna, ben, cara, eve), "d1", 4, dan, "AAAA-AAAA-AAAA-AAAA"), pkt(10, ben, listOf(anna, ben, cara, eve), "AAAA-AAAA-AAAA-AAAA", 5))
        val first = phoneAfter(cara, ps)
        assertEquals(10L, first.ring.current().number); assertEquals("AAAA-AAAA-AAAA-AAAA", first.door)
        for (o in orders(ps)) phoneAfter(cara, o).let { assertEquals(first.ring.current().hash, it.ring.current().hash); assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertEquals(first.ring.all().size, it.ring.all().size) }
    }

    @Test fun aPhoneAwayForTenDays() {
        // Only the latest key is still around, made by someone who isn't an admin.
        val p = phoneAfter(cara, listOf(pkt(12, dan, all, "d1", 1)))
        assertEquals(12L, p.ring.current().number); assertEquals(listOf(anna, ben), p.ring.current().admins)
        // The group is at 12; the phone that is behind makes its own key, numbered below. Members spot it.
        val group = phoneAfter(anna, listOf(pkt(12, dan, all, "d1", 1)))
        val mine = pkt(6, cara, all, "d1", 2, made = now)
        assertTrue(group.ring.behind(mine.r, cara))
        group.get(mine); assertEquals(12L, group.ring.current().number)                      // kept to read with, nothing changes
        // The answer brings it back.
        val back = phoneAfter(cara, listOf(mine, pkt(13, anna, all, "d1", 3, made = now + 1)))
        assertEquals(13L, back.ring.current().number)
    }

    @Test fun aPhoneAwayWhenSomeoneWasRemovedHasToWaitForTheMissingKeys() {
        val r = pkt(8, anna, listOf(anna, ben, cara), "d1", 1, dan, "AAAA-AAAA-AAAA-AAAA")
        val p = phoneAfter(cara, listOf(r)); assertEquals("d1", p.door)                       // it can't follow: epoch 7 isn't here
        p.get(pkt(6, anna, all, "d1", 2)); assertEquals("d1", p.door)
        p.get(pkt(7, anna, all, "d1", 3)); assertEquals("AAAA-AAAA-AAAA-AAAA", p.door)                      // when it comes, the removal is read again
    }

    @Test fun aRemovedPhoneGetsNowhere() {
        val out = pkt(6, anna, listOf(anna, ben, cara), "d1", 1, dan, "AAAA-AAAA-AAAA-AAAA")
        val p = phoneAfter(cara, listOf(out))
        p.get(pkt(7, dan, all, "d1", 2))                                                       // a new key through the old door
        p.get(pkt(7, dan, listOf(cara), "d1", 3, anna, "DDDD-DDDD-DDDD-DDDD"))                              // not an admin
        assertEquals("AAAA-AAAA-AAAA-AAAA", p.door); assertEquals(6L, p.ring.current().number)
        assertTrue(p.ring.removedBefore(dan, now)); assertFalse(p.ring.removedBefore(cara, now))
        // The removed phone stays out, even if rekeys keep coming past it.
        val d = phoneAfter(dan, listOf(out)); assertNotNull(d.removedAt)
        d.get(pkt(7, anna, listOf(anna, ben, cara), "AAAA-AAAA-AAAA-AAAA", 4)); assertEquals(5L, d.ring.current().number)
    }

    @Test fun aStrangerWithAnOldCodeCantFillThePhoneWithKeys() {
        val p = phoneAfter(cara, listOf(pkt(6, anna, all, "d1", 1), pkt(7, anna, listOf(anna, ben, cara), "d1", 2, dan, "AAAA-AAAA-AAAA-AAAA")))
        val before = p.ring.all().size
        p.get(pkt(3, eve, listOf(cara), "d1", 3)); assertEquals(before, p.ring.all().size)      // late, through the old door, from someone who never was in
        p.get(pkt(3, ben, all, "d1", 4)); assertEquals(before + 1, p.ring.all().size)           // from a member: kept to read with
    }

    @Test fun manyRivalsInRandomOrders() {
        val rnd = java.util.Random(42); val admins = listOf(anna, ben, cara)
        fun sha(b: Int) = java.security.MessageDigest.getInstance("SHA-256").digest(secret(b)).joinToString("") { "%02x".format(it) }
        repeat(300) { round ->
            val makers = admins.shuffled(rnd).take(2 + rnd.nextInt(2))              // each admin at most once: a phone numbers its own one after the other
            val rivals = makers.mapIndexed { i, by -> val t = (all - by)[rnd.nextInt(3)]; Triple(pkt(6, by, all - t, "d1", 10 + i, t, "CCCC-CCCC-CCCC-CCC${i + 2}", admins = admins), by, i) }
            val winner = rivals.minWith(compareBy({ admins.indexOf(it.second) }, { sha(10 + it.third) }))
            for (me in all) {
                val p = Phone(me, admins); rivals.map { it.first }.shuffled(rnd).forEach(p::get)
                if (winner.first.r.answers == me) assertNotNull("round $round", p.removedAt)
                else { assertNull("round $round", p.removedAt); assertEquals("round $round", "CCCC-CCCC-CCCC-CCC${winner.third + 2}", p.door) }
            }
        }
    }

    @Test fun crippledRekeysDoNothing() {
        val good = pkt(6, anna, all, "d1", 1, dan, "AAAA-AAAA-AAAA-AAAA").r.encode(); val rnd = java.util.Random(7)
        for (n in good.indices) assertNull(Rekey.decode(good.copyOf(n)))
        repeat(3000) { val b = good.copyOf(); repeat(1 + rnd.nextInt(6)) { b[rnd.nextInt(b.size)] = rnd.nextInt(256).toByte() }; Rekey.decode(b) }
        repeat(1000) { val b = ByteArray(rnd.nextInt(300)).also(rnd::nextBytes); Rekey.decode(b) }
    }
}
