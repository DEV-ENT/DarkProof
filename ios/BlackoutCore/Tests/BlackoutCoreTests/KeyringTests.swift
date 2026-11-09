import XCTest
import CryptoKit
@testable import BlackoutCore

/// Keyring (spec/DESIGN-v0.6-groups.md, "Keys"): the same cases as Android's KeyringTest.
final class KeyringTests: XCTestCase {
    private func secret(_ b: UInt8) -> Data { Data(repeating: b, count: 32) }
    private func hash(_ b: UInt8) -> String { Hex.encode(Data(SHA256.hash(data: secret(b)))) }

    func testCurrentIsTheHighestEpochThenTheSmallestHash() {
        let r = Keyring()
        XCTAssertTrue(r.add(.init(number: 1, made: 1_000, secret: secret(1))))
        XCTAssertFalse(r.add(.init(number: 1, made: 2_000, secret: secret(1)))) // the same secret twice: kept once
        r.add(.init(number: 2, made: 3_000, secret: secret(2))); r.add(.init(number: 2, made: 3_000, secret: secret(3)))
        XCTAssertEqual(r.current.number, 2); XCTAssertEqual(r.current.hash, min(hash(2), hash(3)))
        XCTAssertEqual(r.all.count, 3); XCTAssertTrue(r.all.first === r.current)
    }

    private let anna = "1111111111111111", ben = "2222222222222222", cara = "3333333333333333", dan = "4444444444444444"
    private func rekey(_ epoch: Int64, _ members: [String], admins: [String]? = nil, removes: String? = nil, made: Int64 = 1, answers: String? = nil) -> Rekey {
        Rekey(epoch: epoch, made: made, maker: Data(count: 33), admins: admins ?? [anna], answers: answers ?? removes, parts: members.map { (id: $0, box: Data(count: 1)) }, removal: removes != nil)
    }
    /// Epoch 5: Anna (admin), Ben and Cara.
    private func ring() -> Keyring { let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna])); return r }

    func testOnlyAdminsLeavePeopleOut() {
        XCTAssertNil(ring().admit(rekey(6, [anna, ben]), maker: ben, oldDoor: nil))
        XCTAssertEqual(ring().admit(rekey(6, [anna, ben]), maker: anna, oldDoor: nil), [anna])
    }

    func testTheCodeAloneDoesntLetAnyoneIn() {
        let members = [anna, ben, cara, dan]
        XCTAssertNil(ring().admit(rekey(6, members), maker: dan, oldDoor: nil, now: 2))                       // someone not in yet, adding themselves
        XCTAssertNil(ring().admit(rekey(6, members, admins: [dan]), maker: dan, oldDoor: nil, now: 2))        // and claiming to be the admin
        XCTAssertNil(ring().admit(rekey(6, members, answers: dan), maker: ben, oldDoor: nil, now: 2))         // a member can't add them either
        XCTAssertEqual(ring().admit(rekey(6, members, answers: dan), maker: anna, oldDoor: nil, now: 2), [anna]) // an admin can
        XCTAssertEqual(ring().admit(rekey(6, members, admins: [anna, ben]), maker: anna, oldDoor: nil), [anna, ben])
    }

    func testOnlyAdminsRemoveAndTheRemovedPersonMustBeGone() {
        XCTAssertNil(ring().admit(rekey(6, [anna, ben], removes: cara), maker: ben, oldDoor: nil))
        XCTAssertEqual(ring().admit(rekey(6, [anna, ben], removes: cara), maker: anna, oldDoor: nil), [anna])
        XCTAssertNil(ring().admit(rekey(6, [anna, ben, cara], removes: cara), maker: anna, oldDoor: nil))
    }

    func testAPhoneStillJoiningTakesTheFirstRekey() {
        XCTAssertEqual(Keyring().admit(rekey(6, [dan], admins: [dan]), maker: dan, oldDoor: nil), [dan])
        XCTAssertNil(Keyring().admit(rekey(6, [dan], admins: [dan], removes: cara), maker: dan, oldDoor: "old"))
    }

    func testLateEpochsAreOnlyForReading() {
        let r = ring(); r.add(.init(number: 9, made: 1, secret: secret(9), members: [anna, ben, cara, dan], admins: [anna]))
        XCTAssertNotNil(r.admit(rekey(3, [ben]), maker: ben, oldDoor: nil))
        XCTAssertEqual(r.current.number, 9)
    }

    func testThroughAnOldDoorOnlyARivalRemovalCounts() {
        let r = ring()
        r.add(.init(number: 6, made: 1, secret: secret(6), members: [anna, ben], admins: [anna], code: "new", via: "old", removes: cara, by: anna))
        XCTAssertNotNil(r.admit(rekey(6, [anna, cara], removes: ben), maker: anna, oldDoor: "old"))
        XCTAssertNil(r.admit(rekey(6, [anna, cara]), maker: anna, oldDoor: "old"))
        XCTAssertNil(r.admit(rekey(7, [anna, cara], removes: ben), maker: anna, oldDoor: "old"))
        XCTAssertNil(r.admit(rekey(6, [anna, cara], removes: ben), maker: anna, oldDoor: "another"))
        XCTAssertNil(r.admit(rekey(6, [anna, ben, cara], removes: dan), maker: cara, oldDoor: "old"))
    }

    func testARemovalBeatsAnythingElseOfTheSameNumber() {
        for (a, b) in [(UInt8(1), UInt8(2)), (2, 1), (3, 4), (4, 3)] {
            let r = Keyring()
            r.add(.init(number: 6, made: 1, secret: secret(a), members: [anna, ben, cara], admins: [anna]))
            r.add(.init(number: 6, made: 1, secret: secret(b), members: [anna, ben], admins: [anna], code: "new", via: "old", removes: cara, by: anna))
            XCTAssertEqual(r.current.removes, cara); XCTAssertTrue(r.current === r.lastMove)
        }
    }

    func testTheMostSeniorAdminsRemovalWinsWhateverTheHash() {
        for (a, b) in [(UInt8(1), UInt8(2)), (2, 1), (3, 4), (4, 3)] {
            for seniorFirst in [true, false] {
                let r = Keyring()
                let senior = Keyring.Epoch(number: 6, made: 1, secret: secret(a), members: [anna, cara], admins: [anna], code: "code-a", via: "old", removes: ben, by: anna, rank: 0)
                let junior = Keyring.Epoch(number: 6, made: 1, secret: secret(b), members: [ben, cara], admins: [ben], code: "code-b", via: "old", removes: anna, by: ben, rank: 1)
                for e in seniorFirst ? [senior, junior] : [junior, senior] { r.add(e) }
                XCTAssertTrue(r.current === senior); XCTAssertTrue(r.lastMove === senior); XCTAssertTrue(r.won(senior)); XCTAssertFalse(r.won(junior))
            }
        }
    }

    func testRankIsThePlaceInTheAdminList() {
        let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna, ben]))
        XCTAssertEqual(r.rank(rekey(6, [anna]), maker: anna), 0); XCTAssertEqual(r.rank(rekey(6, [anna]), maker: ben), 1)
        XCTAssertEqual(r.rank(rekey(6, [anna]), maker: cara), .max)
    }

    func testARemovalThatLostSilencesNobody() {
        let r = ring()
        r.add(.init(number: 6, made: 500, secret: secret(6), members: [anna, cara], admins: [anna], code: "code-a", via: "old", removes: ben, by: anna, rank: 0))
        r.add(.init(number: 6, made: 500, secret: secret(7), members: [ben, cara], admins: [ben], code: "code-b", via: "old", removes: anna, by: ben, rank: 1))
        XCTAssertTrue(r.removed(ben, before: 501)); XCTAssertFalse(r.removed(anna, before: 501))
    }

    func testARemovalCantPickAHigherNumberToGetAhead() {
        XCTAssertNil(ring().admit(rekey(9, [anna, cara], removes: ben), maker: anna, oldDoor: nil)) // this phone has no epoch 8
        XCTAssertNotNil(ring().admit(rekey(6, [anna, cara], removes: ben), maker: anna, oldDoor: nil))
    }

    func testOutrankedOnlyByAMoreSeniorRemovalOfTheSameNumber() {
        let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna, ben]))
        XCTAssertFalse(r.outranked(rekey(6, [ben, cara], removes: anna), maker: ben))
        r.add(.init(number: 6, made: 1, secret: secret(6), members: [anna, cara], admins: [anna], code: "code-a", via: "old", removes: ben, by: anna, rank: 0))
        XCTAssertTrue(r.outranked(rekey(6, [ben, cara], removes: anna), maker: ben))
        XCTAssertFalse(r.outranked(rekey(6, [anna, cara], removes: ben), maker: anna))
    }

    func testAKeyDatedLongAgoCantExpireTheOnesBeforeItEarly() {
        let day: Int64 = 24 * 3_600_000, r = Keyring()
        r.add(.init(number: 1, made: 20 * day, secret: secret(1))); r.add(.init(number: 2, made: 0, secret: secret(2)))
        XCTAssertTrue(r.expire(now: 21 * day).isEmpty)
    }

    func testTheWeeklyKeyWaitsForAWeekAndThisPhonesDelay() {
        let day: Int64 = 24 * 3_600_000, hour: Int64 = 3_600_000
        XCTAssertFalse(Keyring.weeklyDue(made: 0, now: 7 * day - 1, delay: 0))
        XCTAssertTrue(Keyring.weeklyDue(made: 0, now: 7 * day, delay: 0))
        XCTAssertFalse(Keyring.weeklyDue(made: 0, now: 7 * day + 2 * hour, delay: 3 * hour))
        XCTAssertTrue(Keyring.weeklyDue(made: 0, now: 7 * day + 3 * hour, delay: 3 * hour))
        XCTAssertFalse(Keyring.overdue(made: 0, now: 7 * day + 6 * hour - 1)); XCTAssertTrue(Keyring.overdue(made: 0, now: 7 * day + 6 * hour))
    }

    func testOneRekeyPerMemberPerHour() {
        let hour: Int64 = 3_600_000, everyone = [anna, ben, cara], now = 100 * hour
        func r() -> Keyring { let k = ring(); k.add(.init(number: 6, made: 50 * hour, secret: secret(6), members: everyone, admins: [anna], by: ben)); return k }
        XCTAssertNil(r().admit(rekey(7, everyone, made: 50 * hour + 1), maker: ben, oldDoor: nil, now: now))
        XCTAssertNotNil(r().admit(rekey(7, everyone, made: 51 * hour), maker: ben, oldDoor: nil, now: now))
        XCTAssertNotNil(r().admit(rekey(7, everyone, made: 50 * hour + 1), maker: cara, oldDoor: nil, now: now))
        let k = r(); k.add(.init(number: 7, made: 50 * hour, secret: secret(7), members: everyone, admins: [anna], by: anna))
        XCTAssertNotNil(k.admit(rekey(8, everyone, made: 50 * hour + 1), maker: anna, oldDoor: nil, now: now))
        XCTAssertNil(r().admit(rekey(7, everyone + [dan], made: 51 * hour, answers: dan), maker: ben, oldDoor: nil, now: now)) // a member can't let someone in
    }

    func testNonsenseNumbersAndTimesAndHugeGroupsAreRefused() {
        let now: Int64 = 1_000_000_000, everyone = [anna, ben, cara]
        for bad in [Int64(0), -1, .min, .max, (1 << 53) + 1] {
            XCTAssertNil(ring().admit(rekey(bad, everyone), maker: anna, oldDoor: nil, now: now))
            XCTAssertNil(Keyring().admit(rekey(bad, everyone), maker: anna, oldDoor: nil, now: now))
            XCTAssertEqual(ring().rank(rekey(bad, everyone), maker: anna), .max) // runs before admit: must not crash
        }
        XCTAssertNil(ring().admit(rekey(1006, everyone), maker: anna, oldDoor: nil, now: now))
        XCTAssertNotNil(ring().admit(rekey(1005, everyone), maker: anna, oldDoor: nil, now: now))
        XCTAssertNil(ring().admit(rekey(6, everyone, made: now + 10 * 60_000 + 1), maker: anna, oldDoor: nil, now: now))
        XCTAssertNil(ring().admit(rekey(6, everyone, made: -1), maker: anna, oldDoor: nil, now: now))
        XCTAssertNil(ring().admit(rekey(6, (1...101).map { String(format: "%016x", $0) }), maker: anna, oldDoor: nil, now: now))
        XCTAssertNotNil(ring().admit(rekey(6, (1...99).map { String(format: "%016x", $0) } + [anna]), maker: anna, oldDoor: nil, now: now))
    }

    func testSomeoneInNoEpochCantMakeAKey() {
        let hour: Int64 = 3_600_000, now = 100 * hour, everyone = [anna, ben, cara], r = ring()
        for i in 0..<8 { XCTAssertNil(r.admit(rekey(6, everyone + [dan], made: now), maker: String(format: "%016x", 100 + i), oldDoor: nil, now: now)) }
        XCTAssertNil(r.admit(rekey(6, everyone, made: now), maker: String(format: "%016x", 200), oldDoor: nil, now: now))
        XCTAssertNotNil(r.admit(rekey(6, everyone, made: now - 2 * hour), maker: ben, oldDoor: nil, now: now))
    }

    func testAFloodOfKeysCantGrowTheRingForever() {
        let r = Keyring()
        for n in Int64(1)...200 { r.add(.init(number: n, made: n, secret: Data((0..<32).map { UInt8(truncatingIfNeeded: n >> Int64($0 % 8)) }))) }
        XCTAssertEqual(r.all.count, 64); XCTAssertEqual(r.current.number, 200); XCTAssertEqual(r.all.map(\.number).min(), 137)
    }

    func testTheEpochBeforeIsPickedTheSameWayOnBothApps() {
        let hashes = [UInt8(1), 2].sorted { hash($0) < hash($1) }
        for order in [hashes, hashes.reversed()] {
            let r = Keyring()
            for b in order { r.add(.init(number: 5, made: 1, secret: secret(b), members: b == hashes[0] ? [anna, ben] : [anna, ben, cara], admins: [anna])) }
            r.add(.init(number: 7, made: 1, secret: secret(9), members: [anna, ben, cara], admins: [anna]))
            XCTAssertNotNil(r.admit(rekey(6, [anna, ben], made: 100), maker: ben, oldDoor: nil, now: 200))
        }
    }

    func testAPhoneThatMissedKeysIsSpotted() {
        let r = Keyring(); r.add(.init(number: 9, made: 1000, secret: secret(9), members: [anna, ben], admins: [anna]))
        XCTAssertTrue(r.behind(rekey(4, [ben], made: 2000), maker: ben))
        XCTAssertFalse(r.behind(rekey(9, [ben], made: 2000), maker: ben))
        XCTAssertFalse(r.behind(rekey(4, [ben], made: 500), maker: ben))
        XCTAssertFalse(r.behind(rekey(4, [cara], made: 2000), maker: cara))
        XCTAssertFalse(r.behind(rekey(4, [ben], removes: cara, made: 2000), maker: ben))
    }

    func testWhatsAboveARemovalGoesAndTheRemovedStaySilent() {
        let r = ring()
        r.add(.init(number: 6, made: 500, secret: secret(6), members: [anna, ben], admins: [anna], code: "new", via: "old", removes: cara, by: anna))
        r.add(.init(number: 8, made: 1, secret: secret(8)))
        r.dropAbove(6); XCTAssertEqual(r.current.number, 6)
        XCTAssertFalse(r.removed(cara, before: 500)); XCTAssertTrue(r.removed(cara, before: 501)); XCTAssertFalse(r.removed(ben, before: 501))
    }

    func testOldEpochsGoButNeverTheCurrentOne() {
        let day: Int64 = 24 * 3_600_000, r = Keyring()
        r.add(.init(number: 1, made: 0, secret: secret(1))); r.add(.init(number: 2, made: 6 * day, secret: secret(2)))
        XCTAssertTrue(r.expire(now: 8 * day).isEmpty) // replaced 2 days ago: a message written on its last day can still come
        XCTAssertEqual(r.expire(now: 14 * day).map(\.number), [1])
        XCTAssertEqual(r.all.map(\.number), [2])
        XCTAssertTrue(r.expire(now: 30 * day).isEmpty) // the current one stays, however old
    }

    func testGroupIdIsStableAndKeysComeFromTheSecret() {
        XCTAssertEqual(GroupCrypto(code: "test-group-1").groupId(), "ccb162da8b97168602926c8bb8f8f4c6") // Python, like Android
        XCTAssertEqual(GroupCrypto.fromSecret(GroupCrypto.deriveKey("test-group-1")).groupId(), GroupCrypto(code: "test-group-1").groupId())
        XCTAssertEqual(GroupCrypto.fromSecret(GroupCrypto.deriveKey("test-group-1")).mailbox, GroupCrypto(code: "test-group-1").mailbox)
    }
}
