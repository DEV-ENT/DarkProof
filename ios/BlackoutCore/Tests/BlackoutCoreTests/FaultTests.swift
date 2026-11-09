import XCTest
import CryptoKit
@testable import BlackoutCore

/// Simulated phones running the real decision code (`Keyring.take`), given the same new keys in every order
/// (spec/DESIGN-v0.6-groups.md, step 6). The same cases as Android's FaultTest.
final class FaultTests: XCTestCase {
    private let anna = "1111111111111111", ben = "2222222222222222", cara = "3333333333333333", dan = "4444444444444444", eve = "5555555555555555"
    private var all: [String] { [anna, ben, cara, dan] }
    private let now: Int64 = 1_000_000_000_000, hour: Int64 = 3_600_000

    private func secret(_ b: UInt8) -> Data { Data(repeating: b, count: 32) }

    private struct Pkt { let r: Rekey, maker: String, door: String }

    /// Number `n`, by `by`, sealed for `members`, through code `door`. `removes`: a removal to the new code `code`.
    private func pkt(_ n: Int64, _ by: String, _ members: [String], _ door: String, _ s: UInt8, removes: String? = nil, code: String? = nil,
                     admins: [String]? = nil, answers: String? = nil, made: Int64? = nil) -> Pkt {
        Pkt(r: Rekey(epoch: n, made: made ?? now - 100 * hour + n * hour, maker: Data(count: 33), admins: (admins ?? [anna, ben]).filter(members.contains),
                     answers: answers ?? removes, parts: members.map { (id: $0, box: Rekey.box(secret(s), code: code)) }, removal: removes != nil), maker: by, door: door)
    }

    /// A phone as the engines run one: it reads the store again after every new epoch, oldest first.
    private final class Phone {
        let me: String, ring = Keyring(), now: Int64
        var door = "d1", old: [String] = [], removedAt: (number: Int64, rank: Int)?, seen: [Pkt] = []
        init(_ me: String, epoch: Keyring.Epoch, now: Int64) { self.me = me; self.now = now; ring.add(epoch) }
        func get(_ p: Pkt) { seen.append(p); if tryIt(p) { settle() } }
        private func tryIt(_ p: Pkt) -> Bool {
            guard p.door == door || old.contains(p.door) else { return false }
            switch ring.take(p.r, maker: p.maker, me: me, door: p.door, oldDoor: p.door != door, removedAt: removedAt, now: now, open: { $0 }) {
            case .added(_, let moveTo, let back):
                if back { removedAt = nil }
                if let moveTo, moveTo != door { old.insert(door, at: 0); door = moveTo }
                return true
            case .removed(let n, let r): removedAt = (n, r); return false
            default: return false
            }
        }
        private func settle() { var again = true; while again { again = false; for p in seen.sorted(by: { $0.r.made < $1.r.made }) where tryIt(p) { again = true } } }
    }

    private func phone(_ me: String, admins: [String]? = nil) -> Phone {
        Phone(me, epoch: .init(number: 5, made: now - 200 * hour, secret: secret(99), members: all, admins: admins ?? [anna, ben]), now: now)
    }
    private func after(_ me: String, _ ps: [Pkt]) -> Phone { let p = phone(me); ps.forEach(p.get); return p }
    private func orders(_ l: [Pkt]) -> [[Pkt]] {
        l.count < 2 ? [l] : l.indices.flatMap { i -> [[Pkt]] in var rest = l; let x = rest.remove(at: i); return orders(rest).map { [x] + $0 } }
    }

    func testTwoAdminsRemovingDifferentPeopleAtOnce() {
        let a = pkt(6, anna, [anna, ben, cara], "d1", 1, removes: dan, code: "AAAA-AAAA-AAAA-AAAA"), b = pkt(6, ben, [anna, ben, dan], "d1", 2, removes: cara, code: "BBBB-BBBB-BBBB-BBBB")
        for o in orders([a, b]) {
            for me in [anna, ben] {
                let p = after(me, o)
                XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.current.removes, dan); XCTAssertEqual(p.ring.stillToRemove(), [cara]); XCTAssertNil(p.removedAt)
            }
            let c = after(cara, o); XCTAssertEqual(c.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertNil(c.removedAt) // told first by the removal that lost: undone
            XCTAssertNotNil(after(dan, o).removedAt)
            let finish = pkt(7, anna, [anna, ben], "AAAA-AAAA-AAAA-AAAA", 3, removes: cara, code: "AAAA-AAAA-AAAA-AAA2")
            for me in [anna, ben] { let p = after(me, o + [finish]); XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAA2"); XCTAssertTrue(p.ring.stillToRemove().isEmpty) }
            XCTAssertNotNil(after(cara, o + [finish]).removedAt)
        }
    }

    func testAdminsRemovingEachOther() {
        let a = pkt(6, anna, [anna, cara, dan], "d1", 1, removes: ben, code: "AAAA-AAAA-AAAA-AAAA"), b = pkt(6, ben, [ben, cara, dan], "d1", 2, removes: anna, code: "BBBB-BBBB-BBBB-BBBB")
        for o in orders([a, b]) {
            for me in [anna, cara, dan] {
                let p = after(me, o)
                XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertNil(p.removedAt); XCTAssertTrue(p.ring.stillToRemove().isEmpty); XCTAssertFalse(p.ring.removed(anna, before: now))
            }
            XCTAssertNotNil(after(ben, o).removedAt)
        }
    }

    func testARemovedAdminCantComeBackLater() {
        let out = pkt(6, anna, [anna, cara, dan], "d1", 1, removes: ben, code: "AAAA-AAAA-AAAA-AAAA")
        let join = pkt(7, anna, [anna, cara, dan, eve], "AAAA-AAAA-AAAA-AAAA", 2, admins: [anna], answers: eve)
        let p = after(cara, [out, join, pkt(6, ben, [ben, cara, dan], "d1", 3, removes: anna, code: "BBBB-BBBB-BBBB-BBBB")])
        XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.current.number, 7); XCTAssertFalse(p.ring.removed(anna, before: now))
        let q = after(cara, [out, join, pkt(8, ben, [ben, cara, dan], "d1", 4, removes: anna, code: "BBBB-BBBB-BBBB-BBBB")])
        XCTAssertEqual(q.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(q.ring.current.number, 7)
        XCTAssertEqual(after(cara, [out, pkt(7, ben, all, "d1", 5)]).ring.current.number, 6)
    }

    func testTheCreatorOverrulesANewerAdmin() {
        let out = pkt(6, ben, [ben, cara, dan], "d1", 1, removes: anna, code: "BBBB-BBBB-BBBB-BBBB")
        let join = pkt(7, cara, [ben, cara, dan, eve], "BBBB-BBBB-BBBB-BBBB", 2, admins: [ben], answers: eve)
        let rival = pkt(6, anna, [anna, cara, dan], "d1", 3, removes: ben, code: "AAAA-AAAA-AAAA-AAAA")
        for o in orders([out, join, rival]) {
            let p = after(cara, o); XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.current.number, 6); XCTAssertEqual(p.ring.current.removes, ben)
        }
    }

    func testARemovalBuiltOnOneThatLost() { // Ben removes Dan, then Anna through his new code, while Anna's rival removal was on its way
        let junior = pkt(6, ben, [anna, ben, cara], "d1", 1, removes: dan, code: "BBBB-BBBB-BBBB-BBBB")
        let next = pkt(7, ben, [ben, cara], "BBBB-BBBB-BBBB-BBBB", 2, removes: anna, code: "BBBB-BBBB-BBBB-BBB2")
        let senior = pkt(6, anna, [anna, ben, cara], "d1", 3, removes: dan, code: "AAAA-AAAA-AAAA-AAAA")
        for o in orders([junior, next, senior]) { let p = after(cara, o); XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.current.number, 6) }
    }

    func testNewKeysInEveryOrder() {
        let ps = [pkt(6, anna, all, "d1", 1), pkt(7, ben, all, "d1", 2), pkt(8, anna, all + [eve], "d1", 3, answers: eve),
                  pkt(9, anna, [anna, ben, cara, eve], "d1", 4, removes: dan, code: "AAAA-AAAA-AAAA-AAAA"), pkt(10, ben, [anna, ben, cara, eve], "AAAA-AAAA-AAAA-AAAA", 5)]
        let first = after(cara, ps)
        XCTAssertEqual(first.ring.current.number, 10); XCTAssertEqual(first.door, "AAAA-AAAA-AAAA-AAAA")
        for o in orders(ps) { let p = after(cara, o); XCTAssertEqual(p.ring.current.hash, first.ring.current.hash); XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.all.count, first.ring.all.count) }
    }

    func testAPhoneAwayForTenDays() {
        let p = after(cara, [pkt(12, dan, all, "d1", 1)])
        XCTAssertEqual(p.ring.current.number, 12); XCTAssertEqual(p.ring.current.admins, [anna, ben])
        let group = after(anna, [pkt(12, dan, all, "d1", 1)]), mine = pkt(6, cara, all, "d1", 2, made: now)
        XCTAssertTrue(group.ring.behind(mine.r, maker: cara))
        group.get(mine); XCTAssertEqual(group.ring.current.number, 12)
        XCTAssertEqual(after(cara, [mine, pkt(13, anna, all, "d1", 3, made: now + 1)]).ring.current.number, 13)
    }

    func testAPhoneAwayWhenSomeoneWasRemovedHasToWaitForTheMissingKeys() {
        let p = after(cara, [pkt(8, anna, [anna, ben, cara], "d1", 1, removes: dan, code: "AAAA-AAAA-AAAA-AAAA")]); XCTAssertEqual(p.door, "d1")
        p.get(pkt(6, anna, all, "d1", 2)); XCTAssertEqual(p.door, "d1")
        p.get(pkt(7, anna, all, "d1", 3)); XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA")
    }

    func testARemovedPhoneGetsNowhere() {
        let out = pkt(6, anna, [anna, ben, cara], "d1", 1, removes: dan, code: "AAAA-AAAA-AAAA-AAAA")
        let p = after(cara, [out])
        p.get(pkt(7, dan, all, "d1", 2)); p.get(pkt(7, dan, [cara], "d1", 3, removes: anna, code: "DDDD-DDDD-DDDD-DDDD"))
        XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.current.number, 6)
        XCTAssertTrue(p.ring.removed(dan, before: now)); XCTAssertFalse(p.ring.removed(cara, before: now))
        let d = after(dan, [out]); XCTAssertNotNil(d.removedAt)
        d.get(pkt(7, anna, [anna, ben, cara], "AAAA-AAAA-AAAA-AAAA", 4)); XCTAssertEqual(d.ring.current.number, 5)
    }

    func testAStrangerWithAnOldCodeCantFillThePhoneWithKeys() {
        let p = after(cara, [pkt(6, anna, all, "d1", 1), pkt(7, anna, [anna, ben, cara], "d1", 2, removes: dan, code: "AAAA-AAAA-AAAA-AAAA")])
        let before = p.ring.all.count
        p.get(pkt(3, eve, [cara], "d1", 3)); XCTAssertEqual(p.ring.all.count, before) // late, through the old door, from someone who never was in
        p.get(pkt(3, ben, all, "d1", 4)); XCTAssertEqual(p.ring.all.count, before + 1) // from a member: kept to read with
    }

    func testManyRivalsInRandomOrders() {
        var rnd = SeededRandom(seed: 42); let admins = [anna, ben, cara]
        func sha(_ b: UInt8) -> String { Hex.encode(Data(SHA256.hash(data: secret(b)))) }
        for round in 0..<300 {
            let makers = Array(admins.shuffled(using: &rnd).prefix(2 + Int.random(in: 0...1, using: &rnd))) // each admin at most once: a phone numbers its own one after the other
            let rivals: [(p: Pkt, by: String, i: UInt8)] = makers.enumerated().map { i, by in
                let t = all.filter { $0 != by }[Int.random(in: 0..<3, using: &rnd)]
                return (pkt(6, by, all.filter { $0 != t }, "d1", 10 + UInt8(i), removes: t, code: "CCCC-CCCC-CCCC-CCC\(i + 2)", admins: admins), by, UInt8(i))
            }
            let winner = rivals.min { a, b in
                let x = admins.firstIndex(of: a.by)!, y = admins.firstIndex(of: b.by)!
                return x != y ? x < y : sha(10 + a.i) < sha(10 + b.i)
            }!
            for me in all {
                let p = phone(me, admins: admins)
                for q in rivals.map(\.p).shuffled(using: &rnd) { p.get(q) }
                if winner.p.r.answers == me { XCTAssertNotNil(p.removedAt, "round \(round)") }
                else { XCTAssertNil(p.removedAt, "round \(round)"); XCTAssertEqual(p.door, "CCCC-CCCC-CCCC-CCC\(winner.i + 2)", "round \(round)") }
            }
        }
    }

    /// On iPhone a bad value traps and takes the app down, so this one matters most here.
    func testCrippledRekeysDoNothing() {
        let good = pkt(6, anna, all, "d1", 1, removes: dan, code: "AAAA-AAAA-AAAA-AAAA").r.encode()
        var rnd = SeededRandom(seed: 7)
        for n in 0..<good.count { XCTAssertNil(Rekey.decode(good.prefix(n))) }
        let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: all, admins: [anna]))
        func exercise(_ d: Data) {
            guard let x = Rekey.decode(d) else { return }
            _ = r.take(x, maker: anna, me: cara, door: "d1", oldDoor: false, removedAt: nil, now: now, open: { $0 }) // whatever came out of decode must not crash
            _ = r.behind(x, maker: anna); _ = r.outranked(x, maker: anna)
        }
        for _ in 0..<3000 {
            var b = [UInt8](good)
            for _ in 0...Int.random(in: 0..<6, using: &rnd) { b[Int.random(in: 0..<b.count, using: &rnd)] = UInt8.random(in: 0...255, using: &rnd) }
            exercise(Data(b))
        }
        for _ in 0..<1000 { exercise(Data((0..<Int.random(in: 0..<300, using: &rnd)).map { _ in UInt8.random(in: 0...255, using: &rnd) })) }
    }
}

/// So a failure can be reproduced.
private struct SeededRandom: RandomNumberGenerator {
    var x: UInt64
    init(seed: UInt64) { x = seed &* 0x9E3779B97F4A7C15 | 1 }
    mutating func next() -> UInt64 { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return x }
}
