import XCTest
import CryptoKit
@testable import BlackoutCore

/// Per-message keys (spec "Message keys"). Same cases as Android's MessageKeysTest.
final class MessageKeysTests: XCTestCase {
    private let anna = "1111111111111111", ben = "2222222222222222", secret = Data(repeating: 9, count: 32)
    private let id = "6a44000000000009", ts: Int64 = 1_794_000_123_456
    private func keys() -> MessageKeys { .of(secret, members: [anna, ben]) }

    func testMatchesTheSharedVector() throws {
        let v = try XCTUnwrap(VectorsTests.vectors.first { $0["kind"] == "message-key" })
        let s = Hex.decode(v["secret"]!), outer = MessageKeys.outer(s), g = GroupCrypto.fromSecret(outer)
        XCTAssertEqual(Hex.encode(outer), v["outer"]); XCTAssertEqual(String(g.mailbox), v["mailbox"])
        let mk = try XCTUnwrap(MessageKeys.of(s, members: [v["member_0"]!, v["member_1"]!]).key(1, 5)); XCTAssertEqual(Hex.encode(mk), v["key_1_5"])
        let t = Int64(v["ts"]!)!
        let c = try g.seal(messageKey: mk, index: 1, counter: 5, id: v["id"]!, ts: t, sender: v["sender"]!, name: v["name"]!, text: v["text"]!, iv: Hex.decode(v["iv"]!)) { _ in Hex.decode(v["signature"]!) }
        XCTAssertEqual(Hex.encode(c), v["cipher"]); XCTAssertEqual(String(g.hideTime(t, c)), v["wire_ts"])
        let p = Packet(id: v["id"]!, ts: Int64(v["wire_ts"]!)!, ttl: 16, cipher: Hex.decode(v["cipher"]!))
        XCTAssertEqual(g.header(p)?.index, 1); XCTAssertEqual(g.header(p)?.counter, 5)
        let o = try XCTUnwrap(g.open(messageKey: mk, index: 1, counter: 5, p))
        XCTAssertEqual(o.message.text, v["text"]); XCTAssertEqual(o.message.ts, t); XCTAssertEqual(o.message.sender, v["sender"])
    }

    func testDeletedKeyIsGoneAndTheOthersStay() throws {
        let k = keys(), before = try (0...9).map { try XCTUnwrap(k.key(1, $0)) }
        k.forget(1, 4)
        XCTAssertNil(k.key(1, 4))
        for i in 0...9 where i != 4 { XCTAssertEqual(k.key(1, i), before[i], "key \(i)") }
    }

    func testKeysCanBeDeletedInAnyOrder() {
        let k = keys(), whole = keys()
        var g = SystemRandomNumberGenerator()
        let order = Array(0..<300).shuffled(using: &g)
        order.prefix(150).forEach { k.forget(0, $0) }
        order.prefix(150).forEach { XCTAssertNil(k.key(0, $0)) }
        order.dropFirst(150).forEach { XCTAssertEqual(k.key(0, $0), whole.key(0, $0)) }
    }

    func testEachSenderHasItsOwnKeys() { XCTAssertNotEqual(keys().key(0, 0), keys().key(1, 0)) }
    func testDeletingOneSendersKeyLeavesTheOthers() { let k = keys(); k.forget(0, 3); XCTAssertNotNil(k.key(1, 3)) }

    func testWhatWasDeletedStaysDeletedAfterARestart() throws {
        let k = keys(); k.forget(1, 7); _ = k.takeNext(); _ = k.takeNext()
        let back = try XCTUnwrap(MessageKeys.decode(k.encode()))
        XCTAssertNil(back.key(1, 7)); XCTAssertEqual(back.key(1, 8), keys().key(1, 8)); XCTAssertEqual(back.takeNext(), 2); XCTAssertEqual(back.members, [anna, ben])
    }

    func testNumbersOutsideTheTreeHaveNoKey() { XCTAssertNil(keys().key(0, 65_536)); XCTAssertNil(keys().key(0, -1)); XCTAssertNil(keys().key(5, 0)) }

    func testWhenTheNumbersRunOutThereIsNoNext() throws {
        var d = keys().encode(); d.replaceSubrange(0..<4, with: [0, 1, 0, 0])
        XCTAssertNil(try XCTUnwrap(MessageKeys.decode(d)).takeNext())
    }

    private func epoch() -> Keyring.Epoch { .fresh(number: 6, made: 1, secret: secret, members: [anna, ben], admins: [anna]) }
    private func sealed(_ e: Keyring.Epoch, _ n: Int, forged: Bool = false) throws -> Packet {
        let c = try e.group.seal(messageKey: try XCTUnwrap(e.messageKeys?.key(1, n)), index: 1, counter: n, id: id, ts: ts, sender: ben, name: "Ben", text: "message \(n)") { forged ? Data(count: 64) : try MemberKey.sign(TestKeys.key, $0) }
        return Packet(id: id, ts: e.group.hideTime(ts, c), ttl: 16, cipher: c)
    }

    func testTwoPhonesWithTheSameSecretReadEachOther() throws {
        let o = try XCTUnwrap(epoch().open(try sealed(epoch(), 2)))
        XCTAssertEqual(o.message.text, "message 2"); XCTAssertEqual(o.message.ts, ts); XCTAssertEqual(o.leaf?.counter, 2); XCTAssertEqual(o.leaf?.index, 1)
    }

    func testOnceDeletedTheEpochCantOpenThePacketAgain() throws {
        let e = epoch(), p = try sealed(epoch(), 2)
        try XCTUnwrap(e.open(p)?.leaf).forget()
        XCTAssertNil(e.open(p))
    }

    func testOpeningAloneDoesntDeleteTheKey() throws {
        let e = epoch(), forged = try sealed(epoch(), 3, forged: true)
        XCTAssertNotNil(e.open(forged)); XCTAssertNotNil(e.messageKeys?.key(1, 3))
    }

    func testTheEpochSecretIsntKept() { let e = epoch(); XCTAssertNotEqual(e.secret, secret); XCTAssertEqual(e.secret, MessageKeys.outer(secret)) }

    func testAKeyKeptForReadingStillOpens() throws {
        let e = Keyring.Epoch.fresh(number: 6, made: 1, secret: secret, roster: [anna, ben], members: [], admins: [anna])
        XCTAssertNotNil(e.open(try sealed(epoch(), 1)))
    }

    func testTheCopyKeepsTheMessage() throws {
        let key = Data(repeating: 3, count: 32), e = epoch(), o = try XCTUnwrap(e.open(try sealed(epoch(), 4)))
        let s = try XCTUnwrap(History.open(key: key, id: id, blob: try XCTUnwrap(History.seal(key: key, id: id, group: "group", epoch: e.hash, o, index: 1, counter: 4))))
        XCTAssertEqual(s.opened.message.text, "message 4"); XCTAssertEqual(s.opened.message.ts, ts); XCTAssertEqual(s.epoch, e.hash); XCTAssertEqual(s.group, "group")
        XCTAssertEqual(s.opened.digest, o.digest); XCTAssertEqual(s.opened.signature, o.signature); XCTAssertEqual(s.index, 1); XCTAssertEqual(s.counter, 4)
    }

    func testTheCopyNeedsItsKeyAndId() throws {
        let key = Data(repeating: 3, count: 32), e = epoch(), o = try XCTUnwrap(e.open(try sealed(epoch(), 4)))
        let b = try XCTUnwrap(History.seal(key: key, id: id, group: "group", epoch: e.hash, o, index: 1, counter: 4))
        XCTAssertNil(History.open(key: Data(count: 32), id: id, blob: b)); XCTAssertNil(History.open(key: key, id: "6a4400000000000a", blob: b))
    }

    func testMessageFitsTheSmallestSize() throws { XCTAssertEqual(try sealed(epoch(), 0).encode().count, 163) }
}
